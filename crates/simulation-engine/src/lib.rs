use agentobe_contracts::{MissionBudget, MissionConstraints, sha256_value};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SimulationMetrics {
    pub sla_breach_rate: f64,
    pub average_queue_age_hours: f64,
    pub escalation_rate: f64,
    pub open_workload: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationStep {
    pub sequence: usize,
    pub tool: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    pub state_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationBranchResult {
    pub name: String,
    pub strategy: String,
    pub status: String,
    pub confidence: f64,
    pub assumptions: Vec<String>,
    pub blind_spots: Vec<String>,
    pub metrics: SimulationMetrics,
    pub delta: SimulationMetrics,
    pub steps: Vec<SimulationStep>,
    pub shadow_state: Vec<Value>,
    pub state_hash: String,
    pub reproducible: bool,
}

pub struct SimulationInput<'a> {
    pub tickets: &'a [Value],
    pub constraints: &'a MissionConstraints,
    pub budget: &'a MissionBudget,
    pub tool_scope: &'a [String],
    pub branch_count: i32,
    pub projection_hash: &'a str,
}

pub fn run_ticket_simulation(
    input: SimulationInput<'_>,
) -> Result<Vec<SimulationBranchResult>, String> {
    if input.branch_count < 3
        || input.branch_count > input.budget.max_branches
        || input.branch_count > 4
    {
        return Err(
            "requested branches exceed the mission budget or the three-branch minimum".into(),
        );
    }
    let strategies = [
        "baseline",
        "priority_first",
        "queue_rebalance",
        "capacity_surge",
    ];
    let baseline = input.tickets.to_vec();
    let clock = simulation_clock(&baseline);
    let baseline_metrics = measure(&baseline, &input.constraints.queue_capacity, clock);
    let tools: BTreeSet<_> = input.tool_scope.iter().map(String::as_str).collect();
    let mut output = Vec::new();

    for (index, strategy) in strategies
        .iter()
        .take(input.branch_count as usize)
        .enumerate()
    {
        let mut state = baseline.clone();
        let mut capacity = input.constraints.queue_capacity.clone();
        let mut steps = Vec::new();

        if *strategy == "priority_first" && tools.contains("ticket.priority") {
            for position in 0..state.len() {
                if string(&state[position], "customer_tier") == "enterprise"
                    && string(&state[position], "priority") != "urgent"
                {
                    let target = string(&state[position], "ticket_id");
                    let before = string(&state[position], "priority");
                    set_string(&mut state[position], "priority", "urgent");
                    push_step(
                        &mut steps,
                        input.budget,
                        &state,
                        StepChange {
                            tool: "ticket.priority",
                            summary: format!("Prioritized enterprise ticket {target}."),
                            target: Some(target),
                            before: Some(json!(before)),
                            after: Some(json!("urgent")),
                        },
                    );
                }
            }
        }
        if *strategy == "queue_rebalance" && tools.contains("ticket.queue") {
            let overloaded = most_loaded_queue(&state);
            if let Some(destination) = least_loaded_queue(&state, &capacity, &overloaded)
                && let Some(position) = state.iter().position(|ticket| {
                    string(ticket, "queue") == overloaded && string(ticket, "state") != "closed"
                })
            {
                let target = string(&state[position], "ticket_id");
                set_string(&mut state[position], "queue", &destination);
                push_step(
                    &mut steps,
                    input.budget,
                    &state,
                    StepChange {
                        tool: "ticket.queue",
                        summary: format!("Rebalanced {target} to {destination}."),
                        target: Some(target),
                        before: Some(json!(overloaded)),
                        after: Some(json!(destination)),
                    },
                );
            }
        }
        if *strategy == "capacity_surge" && tools.contains("ticket.capacity") {
            let queue = most_loaded_queue(&state);
            let before = *capacity.get(&queue).unwrap_or(&1);
            capacity.insert(queue.clone(), before + 2);
            push_step(
                &mut steps,
                input.budget,
                &state,
                StepChange {
                    tool: "ticket.capacity",
                    summary: format!("Added two simulated capacity units to {queue}."),
                    target: Some(queue),
                    before: Some(json!(before)),
                    after: Some(json!(before + 2)),
                },
            );
        }

        let metrics = measure(&state, &capacity, clock);
        push_step(
            &mut steps,
            input.budget,
            &state,
            StepChange {
                tool: "simulation.measure",
                summary: "Measured branch outcomes using the fixed simulation clock.".into(),
                target: None,
                before: None,
                after: Some(serde_json::to_value(&metrics).unwrap()),
            },
        );
        let status = if state.is_empty() {
            "inconclusive"
        } else {
            "completed"
        };
        let state_hash = sha256_value(
            &json!({"projectionHash": input.projection_hash, "strategy": strategy, "capacity": capacity, "state": state, "metrics": metrics}),
        );
        output.push(SimulationBranchResult {
            name: if index == 0 { "Baseline".into() } else { title(strategy) }, strategy: (*strategy).into(), status: status.into(),
            confidence: if status == "completed" { 0.78 } else { 0.2 },
            assumptions: vec![
                "Queue capacity is constant for the simulated observation window.".into(),
                "Priority and queue changes affect waiting time but do not create production side effects.".into(),
                format!("Input is fixed to projection {}.", &input.projection_hash[..input.projection_hash.len().min(12)]),
            ],
            blind_spots: vec!["Customer replies and staffing changes are not modeled.".into(), "Resolution quality and agent skill variance are not modeled.".into()],
            delta: metric_delta(&metrics, &baseline_metrics), metrics, steps, shadow_state: state, state_hash, reproducible: true,
        });
    }
    Ok(output)
}

struct StepChange<'a> {
    tool: &'a str,
    summary: String,
    target: Option<String>,
    before: Option<Value>,
    after: Option<Value>,
}

fn push_step(
    steps: &mut Vec<SimulationStep>,
    budget: &MissionBudget,
    state: &[Value],
    change: StepChange<'_>,
) {
    if steps.len() >= budget.max_steps_per_branch as usize {
        return;
    }
    steps.push(SimulationStep {
        sequence: steps.len() + 1,
        tool: change.tool.into(),
        summary: change.summary,
        target: change.target,
        before: change.before,
        after: change.after,
        state_hash: sha256_value(&Value::Array(state.to_vec())),
    });
}

fn measure(
    tickets: &[Value],
    capacity: &BTreeMap<String, i32>,
    clock: DateTime<Utc>,
) -> SimulationMetrics {
    let active: Vec<_> = tickets
        .iter()
        .filter(|ticket| !matches!(string(ticket, "state").as_str(), "closed" | "resolved"))
        .collect();
    let mut breaches = 0usize;
    let mut escalated = 0usize;
    let mut age_total = 0.0;
    let mut positions = BTreeMap::<String, i32>::new();
    for ticket in &active {
        let queue = string(ticket, "queue");
        let position = positions.entry(queue.clone()).or_default();
        *position += 1;
        let units = (*capacity.get(&queue).unwrap_or(&1)).max(1);
        let priority_factor = match string(ticket, "priority").as_str() {
            "urgent" => 0.35,
            "high" => 0.6,
            _ => 1.0,
        };
        let wait_minutes =
            ((*position as f64 / units as f64).ceil() * 240.0 * priority_factor).round() as i64;
        let completion = clock + Duration::minutes(wait_minutes);
        if parse_time(ticket, "sla_due_at").is_some_and(|due| completion > due) {
            breaches += 1;
        }
        if matches!(string(ticket, "priority").as_str(), "urgent" | "high") {
            escalated += 1;
        }
        if let Some(created) = parse_time(ticket, "created_at") {
            age_total += (clock - created).num_seconds().max(0) as f64 / 3600.0;
        }
    }
    let divisor = active.len().max(1) as f64;
    SimulationMetrics {
        sla_breach_rate: round(breaches as f64 / divisor * 100.0),
        average_queue_age_hours: round(age_total / divisor),
        escalation_rate: round(escalated as f64 / divisor * 100.0),
        open_workload: active.len() as i64,
    }
}

fn simulation_clock(tickets: &[Value]) -> DateTime<Utc> {
    tickets
        .iter()
        .flat_map(|ticket| {
            [
                parse_time(ticket, "updated_at"),
                parse_time(ticket, "created_at"),
            ]
        })
        .flatten()
        .max()
        .unwrap_or(DateTime::UNIX_EPOCH)
        + Duration::hours(1)
}
fn parse_time(value: &Value, key: &str) -> Option<DateTime<Utc>> {
    value.get(key)?.as_str()?.parse().ok()
}
fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(if key == "queue" { "unassigned" } else { "" })
        .to_owned()
}
fn set_string(value: &mut Value, key: &str, replacement: &str) {
    if let Some(map) = value.as_object_mut() {
        map.insert(key.into(), Value::String(replacement.into()));
    }
}
fn most_loaded_queue(tickets: &[Value]) -> String {
    let mut counts = BTreeMap::<String, usize>::new();
    for ticket in tickets {
        *counts.entry(string(ticket, "queue")).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .map(|x| x.0)
        .unwrap_or_else(|| "unassigned".into())
}
fn least_loaded_queue(
    tickets: &[Value],
    capacity: &BTreeMap<String, i32>,
    excluded: &str,
) -> Option<String> {
    let mut counts = BTreeMap::<String, usize>::new();
    for ticket in tickets {
        *counts.entry(string(ticket, "queue")).or_default() += 1;
    }
    capacity
        .keys()
        .filter(|q| q.as_str() != excluded)
        .min_by(|a, b| {
            let ar = *counts.get(*a).unwrap_or(&0) as f64 / *capacity.get(*a).unwrap() as f64;
            let br = *counts.get(*b).unwrap_or(&0) as f64 / *capacity.get(*b).unwrap() as f64;
            ar.total_cmp(&br)
        })
        .cloned()
}
fn metric_delta(current: &SimulationMetrics, baseline: &SimulationMetrics) -> SimulationMetrics {
    SimulationMetrics {
        sla_breach_rate: round(current.sla_breach_rate - baseline.sla_breach_rate),
        average_queue_age_hours: round(
            current.average_queue_age_hours - baseline.average_queue_age_hours,
        ),
        escalation_rate: round(current.escalation_rate - baseline.escalation_rate),
        open_workload: current.open_workload - baseline.open_workload,
    }
}
fn title(value: &str) -> String {
    value
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn round(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentobe_contracts::{MissionBudget, MissionConstraints};
    #[test]
    fn creates_four_isolated_replayable_branches() {
        let tickets = vec![
            json!({"ticket_id":"A","state":"open","priority":"normal","customer_tier":"enterprise","queue":"q1","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T01:00:00Z","sla_due_at":"2026-01-01T03:00:00Z"}),
            json!({"ticket_id":"B","state":"open","priority":"normal","queue":"q1","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T01:00:00Z","sla_due_at":"2026-01-01T04:00:00Z"}),
        ];
        let constraints = MissionConstraints {
            prohibit_ticket_closure: true,
            prohibit_external_messages: true,
            max_p1_age_hours: 24.0,
            queue_capacity: BTreeMap::from([("q1".into(), 1), ("q2".into(), 2)]),
        };
        let budget = MissionBudget {
            max_branches: 4,
            max_steps_per_branch: 20,
            max_runtime_seconds: 60,
        };
        let tools = vec![
            "ticket.priority".into(),
            "ticket.queue".into(),
            "ticket.capacity".into(),
        ];
        let result = run_ticket_simulation(SimulationInput {
            tickets: &tickets,
            constraints: &constraints,
            budget: &budget,
            tool_scope: &tools,
            branch_count: 4,
            projection_hash: &"a".repeat(64),
        })
        .unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(
            result
                .iter()
                .map(|branch| &branch.state_hash)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        assert!(
            result
                .iter()
                .all(|branch| branch.reproducible && !branch.steps.is_empty())
        );
    }
}

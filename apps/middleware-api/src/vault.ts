import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { canonicalJson, sha256 } from "@agentobe/contracts";

export interface BlobStore {
  readonly driver: "file" | "spaces" | "memory";
  put(key: string, data: Uint8Array): Promise<void>;
  get(key: string): Promise<Uint8Array>;
  delete(key: string): Promise<void>;
}

export interface VaultObjectMetadata {
  objectKey: string;
  storageDriver: BlobStore["driver"];
  encryptionAlgorithm: "AES-256-GCM";
  keyWrapAlgorithm: "AES-256-GCM";
  keyVersion: string;
  plaintextHash: string;
  ciphertextHash: string;
  sizeBytes: number;
}

interface EncryptedEnvelope {
  format: "agentobe.source-vault.v1";
  keyVersion: string;
  wrappedKey: CipherPayload;
  content: CipherPayload;
}

interface CipherPayload {
  iv: string;
  tag: string;
  ciphertext: string;
}

export class FileBlobStore implements BlobStore {
  readonly driver = "file" as const;
  constructor(private readonly root: string) {}
  async put(key: string, data: Uint8Array) {
    const path = join(this.root, key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, data, { flag: "wx", mode: 0o600 });
  }
  async get(key: string) {
    return readFile(join(this.root, key));
  }
  async delete(key: string) {
    await unlink(join(this.root, key)).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}

export class MemoryBlobStore implements BlobStore {
  readonly driver = "memory" as const;
  private readonly objects = new Map<string, Uint8Array>();
  async put(key: string, data: Uint8Array) {
    if (this.objects.has(key)) throw new Error(`Object already exists: ${key}`);
    this.objects.set(key, Uint8Array.from(data));
  }
  async get(key: string) {
    const value = this.objects.get(key);
    if (!value) throw new Error(`Object not found: ${key}`);
    return Uint8Array.from(value);
  }
  async delete(key: string) {
    this.objects.delete(key);
  }
}

export class SpacesBlobStore implements BlobStore {
  readonly driver = "spaces" as const;
  private readonly client: S3Client;
  constructor(
    private readonly bucket: string,
    region: string,
    accessKeyId: string,
    secretAccessKey: string,
  ) {
    this.client = new S3Client({
      endpoint: `https://${region}.digitaloceanspaces.com`,
      region,
      credentials: { accessKeyId, secretAccessKey },
    });
  }
  async put(key: string, data: Uint8Array) {
    await this.client.send(new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: data,
      ACL: "private",
      ContentType: "application/vnd.agentobe.encrypted+json",
    }));
  }
  async get(key: string) {
    const result = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    if (!result.Body) throw new Error(`Spaces object has no body: ${key}`);
    return result.Body.transformToByteArray();
  }
  async delete(key: string) {
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
  }
}

export class EncryptedSourceVault {
  private readonly masterKey: Buffer;
  constructor(
    private readonly blobStore: BlobStore,
    masterKeyBase64: string,
    private readonly keyVersion: string,
  ) {
    this.masterKey = Buffer.from(masterKeyBase64, "base64");
    if (this.masterKey.length !== 32) {
      throw new Error("VAULT_MASTER_KEY must be a base64-encoded 32-byte key.");
    }
  }

  async put(workspaceId: string, batchId: string, value: unknown): Promise<VaultObjectMetadata> {
    const plaintext = Buffer.from(canonicalJson(value), "utf8");
    const dataKey = randomBytes(32);
    const envelope: EncryptedEnvelope = {
      format: "agentobe.source-vault.v1",
      keyVersion: this.keyVersion,
      wrappedKey: encrypt(this.masterKey, dataKey),
      content: encrypt(dataKey, plaintext),
    };
    const encoded = Buffer.from(canonicalJson(envelope), "utf8");
    const objectKey = `source-vault/${workspaceId}/${batchId}.json.enc`;
    await this.blobStore.put(objectKey, encoded);
    return {
      objectKey,
      storageDriver: this.blobStore.driver,
      encryptionAlgorithm: "AES-256-GCM",
      keyWrapAlgorithm: "AES-256-GCM",
      keyVersion: this.keyVersion,
      plaintextHash: sha256(plaintext.toString("utf8")),
      ciphertextHash: createHash("sha256").update(encoded).digest("hex"),
      sizeBytes: encoded.byteLength,
    };
  }

  async verify(metadata: VaultObjectMetadata) {
    const encoded = Buffer.from(await this.blobStore.get(metadata.objectKey));
    const ciphertextHash = createHash("sha256").update(encoded).digest("hex");
    const envelope = JSON.parse(encoded.toString("utf8")) as EncryptedEnvelope;
    const dataKey = decrypt(this.masterKey, envelope.wrappedKey);
    const plaintext = decrypt(dataKey, envelope.content);
    const plaintextHash = sha256(plaintext.toString("utf8"));
    return {
      status:
        ciphertextHash === metadata.ciphertextHash && plaintextHash === metadata.plaintextHash
          ? "healthy"
          : "failed",
      ciphertextHash,
      plaintextHash,
      keyVersion: envelope.keyVersion,
      encryptionAlgorithm: metadata.encryptionAlgorithm,
    };
  }

  delete(objectKey: string) {
    return this.blobStore.delete(objectKey);
  }
}

function encrypt(key: Buffer, plaintext: Uint8Array): CipherPayload {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function decrypt(key: Buffer, payload: CipherPayload): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(payload.iv, "base64"));
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]);
}

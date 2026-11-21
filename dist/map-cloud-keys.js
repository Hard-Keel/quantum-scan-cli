// Who holds the keys to your cloud data. Reads Terraform/OpenTofu and CloudFormation for storage,
// databases and backups, and notes where the cloud provider holds the encryption keys.
// Provider-held keys protect against a stolen disk, not against the provider, an insider there,
// or a legal demand made to them. For data no third party should be able to read, encrypt it
// before it leaves your hands, or keep the keys yourself.
// Advice only: it is listed in the map report and does not change the readiness score.
export const CUSTODY_FIX = {
    provider: "The provider holds the keys, so it can read this data. Encrypt sensitive data before it's uploaded (client-side encryption), or use keys you hold: an external key store such as AWS KMS External Key Store, Google Cloud External Key Manager or Azure Key Vault Managed HSM with your own keys.",
    "provider-kms": "You manage the key, but it lives in the provider's key service, so the provider could still use it. For data no third party should read, encrypt it before upload or move the key to an external key store you hold.",
};
/** Resource types we know, what they hold, and which keys name a key you chose. */
const TF = {
    aws_s3_bucket_server_side_encryption_configuration: { kind: "storage", keyAttr: /kms_master_key_id\s*=/, defaultOn: true },
    aws_db_instance: { kind: "database", keyAttr: /kms_key_id\s*=/, needsOn: /storage_encrypted\s*=\s*true/ },
    aws_rds_cluster: { kind: "database", keyAttr: /kms_key_id\s*=/, needsOn: /storage_encrypted\s*=\s*true/ },
    aws_docdb_cluster: { kind: "database", keyAttr: /kms_key_id\s*=/, needsOn: /storage_encrypted\s*=\s*true/ },
    aws_neptune_cluster: { kind: "database", keyAttr: /kms_key_arn\s*=/, needsOn: /storage_encrypted\s*=\s*true/ },
    aws_redshift_cluster: { kind: "database", keyAttr: /kms_key_id\s*=/, needsOn: /encrypted\s*=\s*true/ },
    aws_dynamodb_table: { kind: "database", keyAttr: /kms_key_arn\s*=/, defaultOn: true },
    aws_ebs_volume: { kind: "disk", keyAttr: /kms_key_id\s*=/, needsOn: /encrypted\s*=\s*true/ },
    aws_efs_file_system: { kind: "storage", keyAttr: /kms_key_id\s*=/, needsOn: /encrypted\s*=\s*true/ },
    aws_backup_vault: { kind: "backup", keyAttr: /kms_key_arn\s*=/, defaultOn: true },
    aws_sqs_queue: { kind: "storage", keyAttr: /kms_master_key_id\s*=/, needsOn: /sqs_managed_sse_enabled\s*=\s*true|kms_master_key_id/ },
    google_storage_bucket: { kind: "storage", keyAttr: /default_kms_key_name\s*=/, defaultOn: true },
    google_sql_database_instance: { kind: "database", keyAttr: /encryption_key_name\s*=/, defaultOn: true },
    google_bigquery_dataset: { kind: "database", keyAttr: /kms_key_name\s*=/, defaultOn: true },
    google_compute_disk: { kind: "disk", keyAttr: /kms_key_self_link\s*=|raw_key\s*=|rsa_encrypted_key\s*=/, defaultOn: true },
    azurerm_storage_account: { kind: "storage", keyAttr: /customer_managed_key\s*\{/, defaultOn: true },
    azurerm_mssql_database: { kind: "database", keyAttr: /transparent_data_encryption_key_vault_key_id\s*=/, defaultOn: true },
    azurerm_postgresql_flexible_server: { kind: "database", keyAttr: /customer_managed_key\s*\{/, defaultOn: true },
    azurerm_cosmosdb_account: { kind: "database", keyAttr: /key_vault_key_id\s*=/, defaultOn: true },
};
const KIND_WORD = { storage: "Cloud storage", database: "Cloud database", backup: "Cloud backups", disk: "Cloud disk" };
function title(kind, c) {
    return c === "provider" ? `${KIND_WORD[kind]} encrypted with keys the provider holds` : `${KIND_WORD[kind]} keys live in the provider's key service`;
}
function advice(path, line, resource, kind, custody) {
    return { target: `${path}:${line}`, resource, kind, custody, ruleId: custody === "provider" ? "cloud-provider-held-keys" : "cloud-keys-in-provider-kms", title: title(kind, custody), fix: CUSTODY_FIX[custody] };
}
const strip = (s) => s.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/#.*$|\/\/.*$/, "");
/** Terraform resource blocks: type, name, first line (1-based) and body text. */
export function tfResources(text) {
    const lines = text.split("\n");
    const out = [];
    for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(/^\s*resource\s+"([a-z0-9_]+)"\s+"([A-Za-z0-9_-]+)"\s*\{/);
        if (!m)
            continue;
        let depth = 0;
        let j = i;
        for (; j < lines.length; j++) {
            for (const ch of strip(lines[j])) {
                if (ch === "{")
                    depth++;
                else if (ch === "}")
                    depth--;
            }
            if (depth <= 0)
                break;
        }
        out.push({ type: m[1], name: m[2], line: i + 1, body: lines.slice(i + 1, j).map((l) => l.replace(/^\s*(#|\/\/).*$/, "")).join("\n") });
        i = j;
    }
    return out;
}
export function cloudKeyAdvice(path, text) {
    const p = path.toLowerCase();
    const out = [];
    if (/\.(tf|hcl)$/.test(p)) {
        const res = tfResources(text);
        // An Azure storage account can get its key from a separate resource in the same file.
        const separateAzureKey = res.some((r) => r.type === "azurerm_storage_account_customer_managed_key");
        for (const r of res) {
            const spec = TF[r.type];
            if (!spec)
                continue;
            if (spec.needsOn && !spec.needsOn.test(r.body))
                continue; // encryption off is already a finding of its own
            const id = `${r.type}.${r.name}`;
            if (r.type === "aws_s3_bucket_server_side_encryption_configuration") {
                const own = !/sse_algorithm\s*=\s*"AES256"/.test(r.body) && spec.keyAttr.test(r.body);
                out.push(advice(path, r.line, id, spec.kind, own ? "provider-kms" : "provider"));
                continue;
            }
            // A customer-supplied key (raw_key or rsa_encrypted_key) is one you hold: Google keeps only a hash of it.
            if (r.type === "google_compute_disk" && /raw_key\s*=|rsa_encrypted_key\s*=/.test(r.body))
                continue;
            if (r.type === "azurerm_storage_account" && separateAzureKey) {
                out.push(advice(path, r.line, id, spec.kind, "provider-kms"));
                continue;
            }
            out.push(advice(path, r.line, id, spec.kind, spec.keyAttr.test(r.body) ? "provider-kms" : "provider"));
        }
    }
    else if (/\.(ya?ml|json|template)$/.test(p) && /AWSTemplateFormatVersion|AWS::/.test(text)) {
        const lines = text.split("\n");
        lines.forEach((l, i) => {
            const m = l.match(/["']?SSEAlgorithm["']?\s*:\s*["']?(AES256|aws:kms)["']?/);
            if (!m)
                return;
            // The key can sit just before or just after (JSON tools often sort keys, putting KMSMasterKeyID first).
            const near = lines.slice(Math.max(0, i - 3), i + 4).join("\n");
            const custody = m[1] === "AES256" || !/KMSMasterKeyID/.test(near) ? "provider" : "provider-kms";
            out.push(advice(path, i + 1, "S3 bucket encryption", "storage", custody));
        });
    }
    return out;
}

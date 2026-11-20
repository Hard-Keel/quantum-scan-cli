import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/scan.ts";
import { tlsMinVersionIsWeak, wantsFullFile } from "../src/infra.ts";
import { checkConclusion, prComment } from "../src/report.ts";

const infra = (path: string, src: string) =>
  scanFile(path, src)
    .filter((f) => f.ruleId.startsWith("infra-") || f.kind === "config")
    .map((f) => `${f.algorithm}@${f.line}`);

test("tls min version parsing", () => {
  for (const v of ["TLSv1", "TLSv1_2016", "TLSv1.1_2016", "TLS1_0", "1.0", "1.1", "SSLv3", "ELBSecurityPolicy-2016-08", "Policy-Min-TLS-1-0-2019-07"]) {
    assert.equal(tlsMinVersionIsWeak(v), true, v);
  }
  for (const v of ["TLSv1.2_2021", "TLS1_2", "1.2", "1.3", "TLSv1.3", "ELBSecurityPolicy-TLS13-1-2-2021-06", "Policy-Min-TLS-1-2-2019-07"]) {
    assert.equal(tlsMinVersionIsWeak(v), false, v);
  }
});

test("nginx: weak protocols and ciphers, negations ignored", () => {
  const src = [
    "server {",
    "  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;",
    "  ssl_ciphers HIGH:!aNULL:!MD5:!RC4;",
    "}",
    "server {",
    "  ssl_protocols TLSv1.2 TLSv1.3;",
    "  ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA';",
    "}",
  ].join("\n");
  assert.deepEqual(infra("deploy/nginx/site.conf", src), ["TLS 1.0/1.1@2", "Weak TLS ciphers@7"]);
});

test("apache: SSLProtocol with all minus old versions is fine", () => {
  const ok = "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite HIGH:!aNULL:!MD5";
  assert.deepEqual(infra("conf/httpd-ssl.conf", ok), []);
  const bad = "SSLProtocol all -SSLv3";
  assert.deepEqual(infra("conf/httpd-ssl.conf", bad), ["TLS 1.0/1.1@1"]);
});

test("terraform: open SSH ingress fails, open HTTPS and egress do not", () => {
  const src = [
    'resource "aws_security_group" "web" {',
    "  ingress {",
    "    from_port   = 443",
    "    to_port     = 443",
    '    protocol    = "tcp"',
    '    cidr_blocks = ["0.0.0.0/0"]',
    "  }",
    "  ingress {",
    "    from_port   = 22",
    "    to_port     = 22",
    '    protocol    = "tcp"',
    '    cidr_blocks = ["0.0.0.0/0"]',
    "  }",
    "  egress {",
    "    from_port   = 0",
    "    to_port     = 0",
    '    protocol    = "-1"',
    '    cidr_blocks = ["0.0.0.0/0"]',
    "  }",
    "}",
  ].join("\n");
  const fs = scanFile("infra/main.tf", src).filter((f) => f.kind === "config");
  assert.equal(fs.length, 1);
  assert.equal(fs[0].line, 12);
  assert.match(fs[0].title, /SSH \(22\)/);
  assert.equal(fs[0].risk, "exposed");
  assert.equal(checkConclusion(fs), "failure");
});

test("terraform: encryption off, public bucket, public database, weak TLS policy, key spec", () => {
  const src = [
    'resource "aws_db_instance" "db" {',
    "  storage_encrypted   = false",
    "  publicly_accessible = true",
    "}",
    'resource "aws_s3_bucket_acl" "b" {',
    '  acl = "public-read"',
    "}",
    'resource "aws_lb_listener" "l" {',
    '  ssl_policy = "ELBSecurityPolicy-2016-08"',
    "}",
    'resource "aws_kms_key" "k" {',
    '  customer_master_key_spec = "RSA_2048"',
    "}",
    'resource "aws_cloudfront_distribution" "cdn" {',
    '  viewer_protocol_policy = "allow-all"',
    "}",
  ].join("\n");
  const got = infra("main.tf", src);
  for (const want of ["Encryption at rest off@2", "Public database@3", "Public storage@6", "TLS 1.0/1.1@9", "Unencrypted traffic allowed@15"]) {
    assert.ok(got.includes(want), `${want} in ${got}`);
  }
  assert.ok(got.some((g) => g.startsWith("RSA") && g.endsWith("@12")), got.join(","));
});

test("terraform: variables, placeholders and true settings are not findings", () => {
  const src = [
    'resource "aws_db_instance" "db" {',
    "  storage_encrypted   = var.encrypted",
    "  publicly_accessible = false",
    "  password            = var.db_password",
    "}",
    'resource "aws_s3_bucket_public_access_block" "b" {',
    "  block_public_acls = true",
    "}",
  ].join("\n");
  assert.deepEqual(infra("main.tf", src), []);
});

test("terraform: literal password is a secret", () => {
  const fs = scanFile("main.tf", 'resource "aws_db_instance" "db" {\n  password = "Sup3rS3cretValue!"\n}');
  assert.ok(fs.some((f) => f.risk === "secret" && f.line === 2));
  assert.ok(fs.every((f) => !f.snippet.includes("Sup3rS3cretValue")));
});

test("cloudformation: open RDP ingress and encryption off", () => {
  const src = [
    "AWSTemplateFormatVersion: '2010-09-09'",
    "Resources:",
    "  Sg:",
    "    Type: AWS::EC2::SecurityGroup",
    "    Properties:",
    "      SecurityGroupIngress:",
    "        - IpProtocol: tcp",
    "          FromPort: 3389",
    "          ToPort: 3389",
    "          CidrIp: 0.0.0.0/0",
    "  Db:",
    "    Type: AWS::RDS::DBInstance",
    "    Properties:",
    "      StorageEncrypted: false",
  ].join("\n");
  const got = infra("cfn/stack.yaml", src);
  assert.ok(got.includes("Open to the internet@10"), got.join(","));
  assert.ok(got.includes("Encryption at rest off@14"), got.join(","));
});

test("kubernetes: skip TLS verify and Secret values", () => {
  const src = [
    "apiVersion: v1",
    "kind: Config",
    "clusters:",
    "- cluster:",
    "    insecure-skip-tls-verify: true",
    "---",
    "apiVersion: v1",
    "kind: Secret",
    "metadata:",
    "  name: db",
    "stringData:",
    "  password: hunter2hunter2xyz",
    "  username: admin",
  ].join("\n");
  const got = infra("k8s/app.yaml", src);
  assert.ok(got.includes("TLS verification off@5"), got.join(","));
  assert.ok(got.some((g) => g.endsWith("@12")), got.join(","));
  assert.ok(!got.some((g) => g.endsWith("@13")), got.join(","));
});

test("dockerfile: curl -k and secret in ENV, file paths are fine", () => {
  const src = [
    "FROM node:22",
    "RUN curl -k https://example.com/install.sh | sh",
    "ENV API_TOKEN=abcd1234efgh5678",
    "ENV PASSWORD_FILE=/run/secrets/db",
  ].join("\n");
  const got = infra("Dockerfile", src);
  assert.ok(got.includes("TLS verification off@2"), got.join(","));
  assert.ok(got.some((g) => g.endsWith("@3")), got.join(","));
  assert.ok(!got.some((g) => g.endsWith("@4")), got.join(","));
});

test("test and example paths are skipped for infrastructure checks", () => {
  const src = 'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}';
  assert.deepEqual(infra("examples/basic/main.tf", src), []);
  assert.deepEqual(infra("test/fixtures/main.tf", src), []);
});

test("pull requests judge a changed line in its block", () => {
  const src = [
    'resource "aws_security_group_rule" "r" {',
    '  type        = "ingress"',
    "  from_port   = 5432",
    "  to_port     = 5432",
    '  protocol    = "tcp"',
    '  cidr_blocks = ["0.0.0.0/0"]',
    "}",
  ].join("\n");
  const fs = scanFile("db.tf", src, new Set([6])).filter((f) => f.kind === "config");
  assert.equal(fs.length, 1);
  assert.match(fs[0].title, /PostgreSQL/);
  assert.equal(scanFile("db.tf", src, new Set([2])).filter((f) => f.kind === "config").length, 0);
  assert.ok(wantsFullFile("db.tf", ""));
  assert.ok(!wantsFullFile("package.json", "+  \"name\": \"x\""));
  assert.ok(prComment(fs).includes("Fix before merging"));
});

test("generic secret rule skips names, paths, URLs, settings keys and templates", () => {
  const src = [
    'EnvAuthToken = "ARGOCD_AUTH_TOKEN"',
    'TokenFile = "/var/run/secrets/kubernetes.io/token"',
    '"token_uri": "https://oauth2.googleapis.com/token",',
    'settingsWebhookGitHubSecretKey = "webhook.github.secret"',
    '- "--connection=password={{ .Values.password }}"',
    'apiToken: "YourPingdomApiTokenGoesHere"',
    'token = "xoxb-1234567890-abcdefghijkl"',
  ].join("\n");
  assert.deepEqual(scanFile("app/config.go", src).filter((f) => f.kind === "secret"), []);
});

test("load balancer groups may open all ports; ICMP is not a port", () => {
  const src = [
    "Resources:",
    "  PublicLoadBalancerSG:",
    "    Type: AWS::EC2::SecurityGroup",
    "    Properties:",
    "      SecurityGroupIngress:",
    "        - CidrIp: 0.0.0.0/0",
    "          IpProtocol: -1",
    "  WebSG:",
    "    Type: AWS::EC2::SecurityGroup",
    "    Properties:",
    "      SecurityGroupIngress:",
    "        - IpProtocol: icmp",
    "          FromPort: -1",
    "          ToPort: -1",
    "          CidrIp: 0.0.0.0/0",
  ].join("\n");
  assert.deepEqual(infra("stack.yaml", "AWSTemplateFormatVersion: '2010-09-09'\n" + src), []);
});

test("terraform: a CIDR list written over several lines still counts", () => {
  const src = ['resource "aws_security_group" "web" {', "  ingress {", "    from_port = 22", "    to_port   = 22", '    protocol  = "tcp"', "    cidr_blocks = [", '    "0.0.0.0/0"]', "  }", "}"].join("\n");
  assert.deepEqual(infra("main.tf", src), ["Open to the internet@7"]);
});

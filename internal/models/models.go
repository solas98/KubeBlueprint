package models

// BlueprintRequest is the JSON body sent from the frontend
type BlueprintRequest struct {
	Mode      string   `json:"mode"`      // "helm" | "kustomize"
	AppName   string   `json:"appName"`   // e.g. "my-app"
	Image     string   `json:"image"`     // e.g. "nginx:1.25-alpine"
	Port      string   `json:"port"`      // e.g. "8080" (string to preserve formatting)
	Resources []string `json:"resources"` // selected manifest types
	Envs      []string `json:"envs"`      // ["dev","staging","prod"]
	Security  Security `json:"security"`
	Keda      KedaOpts `json:"keda"`
	Secrets   SecretOpts `json:"secrets"`
	Istio     IstiOpts `json:"istio"`
}

type Security struct {
	NonRoot    bool `json:"nonRoot"`
	ReadOnly   bool `json:"readOnly"`
	DropCaps   bool `json:"dropCaps"`
	Seccomp    bool `json:"seccomp"`
	NoPrivEsc  bool `json:"noPrivEsc"`
	NetPolicy  bool `json:"netPolicy"`
}

type KedaOpts struct {
	Enabled  bool   `json:"enabled"`
	Trigger  string `json:"trigger"`  // "kafka"|"rabbitmq"|"redis"|"sqs"|"prometheus"|"cron"
	// Kafka
	KafkaBootstrapServers string `json:"kafkaBootstrapServers"`
	KafkaTopic            string `json:"kafkaTopic"`
	KafkaConsumerGroup    string `json:"kafkaConsumerGroup"`
	KafkaLagThreshold     string `json:"kafkaLagThreshold"`
	// RabbitMQ
	RabbitMQHost  string `json:"rabbitMQHost"`
	RabbitMQQueue string `json:"rabbitMQQueue"`
	// Redis
	RedisAddress  string `json:"redisAddress"`
	RedisListName string `json:"redisListName"`
	// SQS
	SQSQueueURL string `json:"sqsQueueURL"`
	SQSRegion   string `json:"sqsRegion"`
	// Prometheus
	PrometheusServerAddress string `json:"prometheusServerAddress"`
	PrometheusQuery         string `json:"prometheusQuery"`
	// Cron
	CronTimezone  string `json:"cronTimezone"`
	CronStart     string `json:"cronStart"`
	CronEnd       string `json:"cronEnd"`
	CronDesired   string `json:"cronDesired"`
}

type SecretOpts struct {
	Provider string `json:"provider"` // "none"|"external-secrets"|"vault"
	// External Secrets
	ESSecretStoreName string `json:"esSecretStoreName"`
	ESSecretStoreKind string `json:"esSecretStoreKind"` // "SecretStore"|"ClusterSecretStore"
	ESRemotePath      string `json:"esRemotePath"`
	// Vault
	VaultAddress   string `json:"vaultAddress"`
	VaultRole      string `json:"vaultRole"`
	VaultPath      string `json:"vaultPath"`
	VaultMountPath string `json:"vaultMountPath"`
}

type IstiOpts struct {
	Enabled              bool   `json:"enabled"`
	GatewayName          string `json:"gatewayName"`          // Reference to cluster-scoped Istio Gateway (e.g., "main-gateway")
	MeshGateway          bool   `json:"meshGateway"`          // Include "mesh" gateway for internal traffic (default true)
	VirtualServicePort   string `json:"virtualServicePort"`   // "80" (string for flexibility)
	DestinationRule      bool   `json:"destinationRule"`      // optional
	EnvoyFilter          bool   `json:"envoyFilter"`          // optional
	AuthorizationPolicy  bool   `json:"authorizationPolicy"`  // optional
	AuthzPolicyAction    string `json:"authzPolicyAction"`    // "ALLOW" | "DENY"
}

// GeneratedFile represents a single generated file
type GeneratedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// BlueprintResponse is the JSON response
type BlueprintResponse struct {
	Files []GeneratedFile `json:"files"`
	Mode  string          `json:"mode"`
}

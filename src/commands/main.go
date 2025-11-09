package commands

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"pulsar-js/jwt"
	"strings"
	"time"

	"github.com/apache/pulsar-client-go/pulsar"
	plog "github.com/apache/pulsar-client-go/pulsar/log"
	"github.com/sirupsen/logrus"
)

type App struct {
	Version              bool     `name:"version" short:"v" help:"Display the version."`
	Verbose              bool     `name:"verbose" short:"V" help:"Enable verbose logging."`
	Key                  string   `name:"key" help:"Message key (for routing policy)." group:"Message"`
	OrderingKey          string   `name:"ordering-key" help:"Message ordering key." group:"Message"`
	EventTime            int64    `name:"event-time" help:"Event time for the message (ms since epoch)." group:"Message"`
	ReplicationClusters  []string `name:"replication-cluster" help:"Replication cluster for the message (this can be specified multiple times)." group:"Message"`
	DisableReplication   bool     `name:"disable-replication" help:"Disable replication for the message." group:"Message"`
	SequenceID           int64    `name:"sequence-id" help:"Sequence ID for the message." group:"Message"`
	DeliverAfter         int64    `name:"deliver-after" help:"Delay delivery of the Shared or KeyShared subscription message by specified milliseconds." group:"Message"`
	DeliverAt            int64    `name:"deliver-at" help:"Deliver the Shared or KeyShared subscription message at the specified epoch timestamp in milliseconds." group:"Message"`
	Property             []string `name:"property" short:"p" help:"Add a property to the message in key=value format. Can be specified multiple times." group:"Message"`
	JWT                  string   `help:"Path to JWT file or raw JWT string." group:"OIDC Authentication"`
	AllowUnverifiedJWT   bool     `name:"allow-unverified-jwt" help:"Allow unverified JWT tokens." group:"OIDC Authentication"`
	MTLSCert             string   `name:"mtls-cert" help:"Path to mTLS certificate file." group:"mTLS Authentication"`
	MTLSKey              string   `name:"mtls-key" help:"Path to mTLS key file." group:"mTLS Authentication"`
	CACert               string   `name:"mtls-ca-cert" help:"Path to CA certificate file to verify the Pulsar TLS certificate." group:"mTLS Authentication"`
	OAuthIssuer          string   `name:"oauth2-issuer" help:"URL of the authentication provider which allows the Pulsar client to obtain an access token." group:"OAuth2 Authentication"`
	OAuthPrivateKey      string   `name:"oauth2-private-key" help:"Path to the private key file or raw content used to sign the access token request." group:"OAuth2 Authentication"`
	OAuthAudience        string   `name:"oauth2-audience" help:"The OAuth 2.0 resource server identifier for the pulsar cluster. (ex: the broker URL)" group:"OAuth2 Authentication"`
	OAuthClientID        string   `name:"oauth2-client-id" help:"The OAuth 2.0 client identifier." group:"OAuth2 Authentication"`
	Username             string   `name:"username" help:"Username for basic authentication." group:"Basic Authentication"`
	Password             string   `name:"password" help:"Password for basic authentication." group:"Basic Authentication"`
	AthenzURL            string   `name:"athenz" help:"URL for authentication." group:"Athenz Authentication"`
	AthenzProxyURL       string   `name:"athenz-proxy" help:"Proxy URL for authentication." group:"Athenz Authentication"`
	AthenzProviderDomain string   `name:"athenz-provider-domain" help:"Provider Domain for authentication." default:"pulsar" group:"Athenz Authentication"`
	AthenzTenant         string   `name:"athenz-tenant" help:"Tenant for authentication." group:"Athenz Authentication"`
	AthenzService        string   `name:"athenz-service" help:"Service for authentication." group:"Athenz Authentication"`
	AthenzPrivateKey     string   `name:"athenz-private-key" help:"Path to private key file." group:"Athenz Authentication"`
	AthenzKeyID          string   `name:"athenz-key-id" help:"Private key ID." group:"Athenz Authentication"`
	AthenzCertChain      string   `name:"athenz-cert-chain" help:"Path to Athenz x509 certificate chain file. (required if using Copper Argos)" group:"Athenz Authentication"`
	AthenzCACert         string   `name:"athenz-ca-cert" help:"Path to Athenz CA certificate file. (required if using Copper Argos)" group:"Athenz Authentication"`
	Name                 string   `name:"name" help:"Name of the producer." default:"manual-producer" group:"Producer"`
	Timeout              int64    `name:"timeout" help:"Seconds before publish times out." default:"30" group:"Producer"`
	ProducerProperty     []string `name:"producer-property" help:"Add a property to the producer in key=value format. Can be specified multiple times." group:"Producer"`
	ConnectionString     string   `help:"Server and topic to publish to. Example: pulsar://localhost:5678/public/default/test" arg:"" default:"pulsar://localhost:5678/public/default/test" required:"true"`
	Message              string   `help:"Message to send." arg:"" optional:""`
}

func (c *App) Run(ctx *Context) error {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})

	debug, _ := ctx.Get("debug")
	if debug != nil && debug.(string) == "true" {
		log.SetLevel(logrus.DebugLevel)
	} else if c.Verbose {
		log.SetLevel(logrus.InfoLevel)
	} else {
		log.SetLevel(logrus.WarnLevel)
	}

	pulsarLogger := plog.NewLoggerWithLogrus(log)

	if c.Version {
		version, _ := ctx.Get("version")
		buildTime, _ := ctx.Get("buildTime")
		fmt.Printf("v%s (%s)\n", version, buildTime)
		return nil
	}

	// Validate connection string
	uri, err := url.Parse(c.ConnectionString)
	if err != nil {
		log.Errorf("failed to parse connection string: %v", err)
		os.Exit(1)
	} else if uri.Scheme != "pulsar" && uri.Scheme != "pulsar+ssl" {
		log.Errorf("Unsupported scheme in connection string: %s", uri.Scheme)
		os.Exit(1)
	} else if len(strings.Split(strings.TrimPrefix(uri.Path, "/"), "/")) != 4 {
		log.Errorf("Connection string (%s) must include (non-)persistent, a tenant, namespace, and topic (e.g. pulsar://host:port/public/default/my-topic)", c.ConnectionString)
		os.Exit(1)
	}

	// Placeholder for auth
	var auth pulsar.Authentication

	// Authentication
	if c.JWT != "" {
		// Verify JWT
		token, verified, err := jwt.Verify(c.JWT, log)
		if err != nil {
			log.Errorln(err.Error())
			os.Exit(1)
		}

		if !verified && !c.AllowUnverifiedJWT {
			log.Errorln("JWT verification failed")
			os.Exit(1)
		}

		auth = pulsar.NewAuthenticationToken(token)

		log.WithFields(logrus.Fields{
			"type":     "authentication",
			"verified": verified,
			"value":    "jwt",
		}).Info("config")
	} else if c.MTLSCert != "" {
		auth = pulsar.NewAuthenticationTLS(c.MTLSCert, c.MTLSKey)

		log.WithFields(logrus.Fields{
			"type":  "authentication",
			"value": "mtls",
		}).Info("config")
	} else if c.OAuthClientID != "" {
		if c.OAuthPrivateKey == "" || c.OAuthAudience == "" {
			log.Errorln("OAuth authentication requires --oauth-private-key and --oauth-audience")
			os.Exit(1)
		}
		auth = pulsar.NewAuthenticationOAuth2(map[string]string{
			"type":       "client_credentials",
			"issuerUrl":  c.OAuthIssuer,
			"audience":   c.OAuthAudience,
			"privateKey": c.OAuthPrivateKey,
			"clientId":   c.OAuthClientID,
		})

		log.WithFields(logrus.Fields{
			"type":  "authentication",
			"value": "oauth2",
		}).Info("config")
	} else if c.Username != "" {
		// Basic Authentication
		if c.Password == "" {
			log.Errorln("Basic authentication requires --password")
			os.Exit(1)
		}
		auth, err = pulsar.NewAuthenticationBasic(c.Username, c.Password)
		if err != nil {
			log.Errorf("basic authentication failure: %v", err)
			os.Exit(1)
		}

		log.WithFields(logrus.Fields{
			"type":  "authentication",
			"value": "basic",
		}).Info("config")
	} else if c.AthenzKeyID != "" {
		zts := map[string]string{
			"providerDomain": c.AthenzProviderDomain,
			"tenantDomain":   c.AthenzTenant,
			"tenantService":  c.AthenzService,
			"privateKey":     "file://" + c.AthenzPrivateKey,
			"keyId":          c.AthenzKeyID,
		}

		if c.AthenzProxyURL != "" {
			zts["ztsProxyUrl"] = c.AthenzProxyURL
		} else {
			zts["ztsUrl"] = c.AthenzURL
		}

		if c.AthenzCACert != "" {
			zts["caCert"] = "file://" + c.AthenzCACert
		}

		if c.AthenzCertChain != "" {
			zts["x509CertChain"] = "file://" + c.AthenzCertChain
		}

		// Athenz Authentication
		auth = pulsar.NewAuthenticationAthenz(zts)
		if err != nil {
			log.Errorf("athenz authentication failure: %v", err)
			os.Exit(1)
		}

		log.WithFields(logrus.Fields{
			"type":  "authentication",
			"value": "athenz",
		}).Info("config")
	} else if c.Verbose {
		log.WithFields(logrus.Fields{
			"type":  "authentication",
			"value": "none",
		}).Info("config")
	}

	// Create Pulsar client
	var client pulsar.Client
	port := uri.Port()
	if port == "" || port == "0" || port == ":" {
		if uri.Scheme == "pulsar+ssl" {
			port = "6651"
		} else {
			port = "6650"
		}
	}

	connstring := fmt.Sprintf("%s://%s:%s", uri.Scheme, uri.Hostname(), port)
	if auth != nil {
		if c.MTLSCert != "" && c.CACert != "" {
			client, err = pulsar.NewClient(pulsar.ClientOptions{
				URL:                   connstring,
				Authentication:        auth,
				TLSTrustCertsFilePath: c.CACert,
				Logger:                pulsarLogger,
			})
		} else {
			client, err = pulsar.NewClient(pulsar.ClientOptions{
				URL:            connstring,
				Authentication: auth,
				Logger:         pulsarLogger,
			})
		}

		log.WithFields(logrus.Fields{
			"authenticated":     true,
			"connection_string": connstring,
		}).Info("connect")
	} else {
		client, err = pulsar.NewClient(pulsar.ClientOptions{
			URL:    connstring,
			Logger: pulsarLogger,
		})
		log.WithFields(logrus.Fields{
			"authenticated":     false,
			"connection_string": connstring,
		}).Info("connect")
	}
	if err != nil {
		log.Errorf("failed to create client: %v", err)
		os.Exit(1)
	}
	defer client.Close()

	// Identify topic
	topicParts := strings.Split(strings.TrimPrefix(uri.Path, "/"), "/")
	topic := topicParts[0] + "://" + strings.Join(topicParts[1:], "/")
	log.WithFields(logrus.Fields{
		"topic": topic,
	}).Warn("prepublish")

	// Create producer
	props := make(map[string]string)
	for _, p := range c.ProducerProperty {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) == 2 {
			props[parts[0]] = parts[1]
		}
	}

	producer, err := client.CreateProducer(pulsar.ProducerOptions{
		Name:            c.Name,
		Topic:           topic,
		SendTimeout:     time.Duration(c.Timeout) * time.Second,
		Properties:      props,
		DisableBatching: true,
		EnableChunking:  true,
	})

	if err != nil {
		log.Errorf("failed to create producer: %v", err)
		os.Exit(1)
	}
	defer producer.Close()

	// Construct message
	message := &pulsar.ProducerMessage{
		Payload: []byte(c.Message),
	}

	if c.Key != "" {
		message.Key = c.Key
	}

	if c.OrderingKey != "" {
		message.OrderingKey = c.OrderingKey
	}

	if len(c.Property) > 0 {
		props := make(map[string]string)
		for _, p := range c.Property {
			parts := strings.SplitN(p, "=", 2)
			if len(parts) == 2 {
				props[parts[0]] = parts[1]
			}
		}
		message.Properties = props
	}

	if c.EventTime > 0 {
		seconds := c.EventTime / 1000
		ms := c.EventTime % 1000
		ns := ms * int64(time.Millisecond)
		message.EventTime = time.Unix(seconds, ns)
	}

	if len(c.ReplicationClusters) > 0 {
		message.ReplicationClusters = c.ReplicationClusters
	}

	if c.DisableReplication {
		message.DisableReplication = c.DisableReplication
	}

	if c.SequenceID > 0 {
		message.SequenceID = &c.SequenceID
	}

	if c.DeliverAfter > 0 {
		seconds := c.EventTime / 1000
		ms := c.EventTime % 1000
		ns := ms * int64(time.Millisecond)
		message.DeliverAfter = time.Duration(seconds)*time.Second + time.Duration(ns)
	}

	if c.DeliverAt > 0 {
		seconds := c.EventTime / 1000
		ms := c.EventTime % 1000
		ns := ms * int64(time.Millisecond)
		message.DeliverAt = time.Unix(seconds, ns)
	}

	log.WithFields(logrus.Fields{
		"message": c.Message,
	}).Warn("publish")

	// Send message
	if msgID, err := producer.Send(context.Background(), message); err != nil {
		log.WithFields(logrus.Fields{
			"success": false,
			"error":   err,
		}).Warn("done")
		os.Exit(1)
	} else {
		log.WithFields(logrus.Fields{
			"success":    true,
			"message_id": msgID.String(),
		}).Warn("done")
	}

	return nil
}

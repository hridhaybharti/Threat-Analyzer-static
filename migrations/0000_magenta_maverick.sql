CREATE TABLE "analyses" (
	"id" serial PRIMARY KEY NOT NULL,
	"type" text NOT NULL,
	"input" text NOT NULL,
	"risk_score" integer NOT NULL,
	"risk_level" text NOT NULL,
	"summary" text NOT NULL,
	"details" jsonb NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"is_favorite" boolean DEFAULT false
);

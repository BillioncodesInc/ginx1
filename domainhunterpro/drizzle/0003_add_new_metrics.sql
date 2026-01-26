-- Add new metrics columns from ExpiredDomains.net
ALTER TABLE `domainMetrics` ADD `majesticGlobalRank` integer DEFAULT 0 NOT NULL;
ALTER TABLE `domainMetrics` ADD `inDmoz` integer DEFAULT false NOT NULL;
ALTER TABLE `domainMetrics` ADD `wikipediaLinks` integer DEFAULT 0 NOT NULL;
ALTER TABLE `domainMetrics` ADD `relatedDomains` integer DEFAULT 0 NOT NULL;
ALTER TABLE `domainMetrics` ADD `registeredTlds` integer DEFAULT 0 NOT NULL;

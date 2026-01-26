CREATE TABLE `domainHistory` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domainId` int NOT NULL,
	`snapshotDate` timestamp NOT NULL,
	`contentType` varchar(100),
	`screenshotUrl` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `domainHistory_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `domainMetrics` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domainId` int NOT NULL,
	`backlinksCount` int NOT NULL DEFAULT 0,
	`domainPop` int NOT NULL DEFAULT 0,
	`trustFlow` int NOT NULL DEFAULT 0,
	`citationFlow` int NOT NULL DEFAULT 0,
	`domainAuthority` int NOT NULL DEFAULT 0,
	`archiveSnapshots` int NOT NULL DEFAULT 0,
	`spamScore` int NOT NULL DEFAULT 0,
	`qualityScore` int NOT NULL DEFAULT 0,
	`isDictionaryWord` boolean NOT NULL DEFAULT false,
	`hasCleanHistory` boolean NOT NULL DEFAULT true,
	`lastChecked` timestamp NOT NULL DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `domainMetrics_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `domains` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domainName` varchar(255) NOT NULL,
	`tld` varchar(20) NOT NULL,
	`status` enum('available','registered','pending') NOT NULL DEFAULT 'available',
	`droppedDate` timestamp,
	`birthYear` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `domains_id` PRIMARY KEY(`id`),
	CONSTRAINT `domains_domainName_unique` UNIQUE(`domainName`)
);
--> statement-breakpoint
CREATE TABLE `searchHistory` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int,
	`searchQuery` varchar(255),
	`filtersApplied` json,
	`resultsCount` int NOT NULL DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `searchHistory_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `userFavorites` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`domainId` int NOT NULL,
	`notes` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `userFavorites_id` PRIMARY KEY(`id`)
);

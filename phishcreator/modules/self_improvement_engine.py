#!/usr/bin/env python3
"""
Self-Improvement Engine
Learns from successes and failures to improve future phishlet generation
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class PhishletTestResult:
    """Result of testing a generated phishlet"""
    phishlet_name: str
    target_domain: str
    auth_type: str
    success: bool
    credential_capture: bool
    cookie_capture: bool
    errors: List[str] = field(default_factory=list)
    missing_hosts: List[str] = field(default_factory=list)
    missing_cookies: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence_score: float = 0.0
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class LearningPattern:
    """A learned pattern for phishlet generation"""
    pattern_id: str
    auth_type: str
    domain_pattern: str  # e.g., "*.google.com", "*.microsoft.com"
    success_rate: float
    usage_count: int
    patterns: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


class SelfImprovementEngine:
    """
    Manages learning from phishlet generation attempts
    Stores successful patterns and learns from failures
    """

    # Default database filename
    DEFAULT_DB_NAME = "phishlet_learning.db"

    def __init__(self, db_path: str = None):
        """
        Initialize the learning engine

        Args:
            db_path: Path to SQLite database for storing learning data.
                     If None, uses default path in module directory.
        """
        if db_path is None:
            # Use absolute path in the module's directory
            import os
            module_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(module_dir, self.DEFAULT_DB_NAME)
        else:
            # If relative path provided, make it absolute based on cwd
            import os
            if not os.path.isabs(db_path):
                self.db_path = os.path.abspath(db_path)
            else:
                self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Test results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phishlet_name TEXT NOT NULL,
                target_domain TEXT NOT NULL,
                auth_type TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                credential_capture BOOLEAN NOT NULL,
                cookie_capture BOOLEAN NOT NULL,
                errors TEXT,
                missing_hosts TEXT,
                missing_cookies TEXT,
                confidence_score REAL,
                timestamp TEXT NOT NULL
            )
        """)
        
        # Learning patterns table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learning_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_id TEXT UNIQUE NOT NULL,
                auth_type TEXT NOT NULL,
                domain_pattern TEXT NOT NULL,
                success_rate REAL NOT NULL,
                usage_count INTEGER NOT NULL,
                patterns TEXT NOT NULL,
                metadata TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # Domain-specific optimizations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_optimizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                optimization_type TEXT NOT NULL,
                optimization_data TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
    
    def record_test_result(self, result: PhishletTestResult):
        """
        Record a phishlet test result
        
        Args:
            result: PhishletTestResult object
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO test_results (
                phishlet_name, target_domain, auth_type, success,
                credential_capture, cookie_capture, errors,
                missing_hosts, missing_cookies, confidence_score, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.phishlet_name,
            result.target_domain,
            result.auth_type,
            result.success,
            result.credential_capture,
            result.cookie_capture,
            json.dumps(result.errors),
            json.dumps(result.missing_hosts),
            json.dumps(result.missing_cookies),
            result.confidence_score,
            result.timestamp
        ))
        
        conn.commit()
        conn.close()
        
        # Update learning patterns based on result
        if result.success:
            self._learn_from_success(result)
        else:
            self._learn_from_failure(result)
    
    def _learn_from_success(self, result: PhishletTestResult):
        """Learn from successful phishlet generation"""
        # Extract domain pattern (e.g., google.com -> *.google.com)
        domain_parts = result.target_domain.split('.')
        if len(domain_parts) >= 2:
            domain_pattern = f"*.{'.'.join(domain_parts[-2:])}"
        else:
            domain_pattern = result.target_domain
        
        # Update or create learning pattern
        pattern_id = f"{result.auth_type}_{domain_pattern}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if pattern exists
        cursor.execute("""
            SELECT usage_count, success_rate, patterns
            FROM learning_patterns
            WHERE pattern_id = ?
        """, (pattern_id,))
        
        row = cursor.fetchone()
        
        if row:
            # Update existing pattern
            usage_count, success_rate, patterns_json = row
            usage_count += 1
            success_rate = (success_rate * (usage_count - 1) + 1.0) / usage_count
            
            cursor.execute("""
                UPDATE learning_patterns
                SET usage_count = ?, success_rate = ?, updated_at = ?
                WHERE pattern_id = ?
            """, (usage_count, success_rate, datetime.now().isoformat(), pattern_id))
        else:
            # Create new pattern
            cursor.execute("""
                INSERT INTO learning_patterns (
                    pattern_id, auth_type, domain_pattern, success_rate,
                    usage_count, patterns, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern_id,
                result.auth_type,
                domain_pattern,
                1.0,
                1,
                json.dumps({}),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
        
        conn.commit()
        conn.close()
    
    def _learn_from_failure(self, result: PhishletTestResult):
        """Learn from failed phishlet generation"""
        # Record common failure patterns
        domain_pattern = f"*.{'.'.join(result.target_domain.split('.')[-2:])}"
        pattern_id = f"{result.auth_type}_{domain_pattern}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Update success rate
        cursor.execute("""
            SELECT usage_count, success_rate
            FROM learning_patterns
            WHERE pattern_id = ?
        """, (pattern_id,))
        
        row = cursor.fetchone()
        
        if row:
            usage_count, success_rate = row
            usage_count += 1
            success_rate = (success_rate * (usage_count - 1)) / usage_count
            
            cursor.execute("""
                UPDATE learning_patterns
                SET usage_count = ?, success_rate = ?, updated_at = ?
                WHERE pattern_id = ?
            """, (usage_count, success_rate, datetime.now().isoformat(), pattern_id))
        
        conn.commit()
        conn.close()
    
    def get_similar_patterns(self, target_domain: str, auth_type: str) -> List[LearningPattern]:
        """
        Get similar successful patterns for a domain and auth type
        
        Args:
            target_domain: Target domain
            auth_type: Authentication type
        
        Returns:
            List of LearningPattern objects
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Extract domain pattern
        domain_parts = target_domain.split('.')
        if len(domain_parts) >= 2:
            domain_pattern = f"*.{'.'.join(domain_parts[-2:])}"
        else:
            domain_pattern = target_domain
        
        # Query for similar patterns
        cursor.execute("""
            SELECT pattern_id, auth_type, domain_pattern, success_rate,
                   usage_count, patterns, metadata, created_at, updated_at
            FROM learning_patterns
            WHERE (domain_pattern = ? OR auth_type = ?)
              AND success_rate > 0.5
            ORDER BY success_rate DESC, usage_count DESC
            LIMIT 10
        """, (domain_pattern, auth_type))
        
        patterns = []
        for row in cursor.fetchall():
            pattern = LearningPattern(
                pattern_id=row[0],
                auth_type=row[1],
                domain_pattern=row[2],
                success_rate=row[3],
                usage_count=row[4],
                patterns=json.loads(row[5]),
                metadata=json.loads(row[6]) if row[6] else {},
                created_at=row[7],
                updated_at=row[8]
            )
            patterns.append(pattern)
        
        conn.close()
        return patterns
    
    def get_success_rate(self, target_domain: str, auth_type: str) -> float:
        """
        Get success rate for a domain and auth type combination
        
        Args:
            target_domain: Target domain
            auth_type: Authentication type
        
        Returns:
            Success rate (0.0 to 1.0)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes
            FROM test_results
            WHERE target_domain = ? AND auth_type = ?
        """, (target_domain, auth_type))
        
        row = cursor.fetchone()
        conn.close()
        
        if row and row[0] > 0:
            return row[1] / row[0]
        return 0.0
    
    def get_common_failures(self, target_domain: str) -> Dict[str, int]:
        """
        Get common failure patterns for a domain
        
        Args:
            target_domain: Target domain
        
        Returns:
            Dictionary of failure types and their counts
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT errors, missing_hosts, missing_cookies
            FROM test_results
            WHERE target_domain = ? AND success = 0
        """, (target_domain,))
        
        failure_counts = {
            'missing_hosts': {},
            'missing_cookies': {},
            'errors': {}
        }
        
        for row in cursor.fetchall():
            errors = json.loads(row[0]) if row[0] else []
            missing_hosts = json.loads(row[1]) if row[1] else []
            missing_cookies = json.loads(row[2]) if row[2] else []
            
            for error in errors:
                failure_counts['errors'][error] = failure_counts['errors'].get(error, 0) + 1
            
            for host in missing_hosts:
                failure_counts['missing_hosts'][host] = failure_counts['missing_hosts'].get(host, 0) + 1
            
            for cookie in missing_cookies:
                failure_counts['missing_cookies'][cookie] = failure_counts['missing_cookies'].get(cookie, 0) + 1
        
        conn.close()
        return failure_counts
    
    def suggest_improvements(self, target_domain: str, auth_type: str,
                           current_phishlet: Dict) -> List[str]:
        """
        Suggest improvements based on learning data
        
        Args:
            target_domain: Target domain
            auth_type: Authentication type
            current_phishlet: Current phishlet configuration
        
        Returns:
            List of improvement suggestions
        """
        suggestions = []
        
        # Get similar successful patterns
        similar_patterns = self.get_similar_patterns(target_domain, auth_type)
        
        if similar_patterns:
            best_pattern = similar_patterns[0]
            suggestions.append(
                f"✓ Found similar successful pattern with {best_pattern.success_rate:.0%} success rate "
                f"(used {best_pattern.usage_count} times)"
            )
        
        # Get common failures
        failures = self.get_common_failures(target_domain)
        
        if failures['missing_hosts']:
            most_common_host = max(failures['missing_hosts'], key=failures['missing_hosts'].get)
            suggestions.append(
                f"⚠️ Consider adding proxy host: {most_common_host} "
                f"(missing in {failures['missing_hosts'][most_common_host]} failed attempts)"
            )
        
        if failures['missing_cookies']:
            most_common_cookie = max(failures['missing_cookies'], key=failures['missing_cookies'].get)
            suggestions.append(
                f"⚠️ Consider capturing cookie: {most_common_cookie} "
                f"(missing in {failures['missing_cookies'][most_common_cookie]} failed attempts)"
            )
        
        # Get overall success rate
        success_rate = self.get_success_rate(target_domain, auth_type)
        if success_rate > 0:
            suggestions.append(
                f"ℹ️ Historical success rate for {target_domain} ({auth_type}): {success_rate:.0%}"
            )
        
        return suggestions
    
    def export_learning_data(self, output_path: str):
        """
        Export learning data to JSON file
        
        Args:
            output_path: Path to output JSON file
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Export patterns
        cursor.execute("SELECT * FROM learning_patterns")
        patterns = []
        for row in cursor.fetchall():
            patterns.append({
                'pattern_id': row[1],
                'auth_type': row[2],
                'domain_pattern': row[3],
                'success_rate': row[4],
                'usage_count': row[5],
                'patterns': json.loads(row[6]),
                'metadata': json.loads(row[7]) if row[7] else {},
                'created_at': row[8],
                'updated_at': row[9]
            })
        
        # Export test results
        cursor.execute("SELECT * FROM test_results ORDER BY timestamp DESC LIMIT 100")
        results = []
        for row in cursor.fetchall():
            results.append({
                'phishlet_name': row[1],
                'target_domain': row[2],
                'auth_type': row[3],
                'success': bool(row[4]),
                'credential_capture': bool(row[5]),
                'cookie_capture': bool(row[6]),
                'errors': json.loads(row[7]) if row[7] else [],
                'missing_hosts': json.loads(row[8]) if row[8] else [],
                'missing_cookies': json.loads(row[9]) if row[9] else [],
                'confidence_score': row[10],
                'timestamp': row[11]
            })
        
        conn.close()
        
        # Write to file
        with open(output_path, 'w') as f:
            json.dump({
                'patterns': patterns,
                'recent_results': results,
                'exported_at': datetime.now().isoformat()
            }, f, indent=2)
    
    def import_learning_data(self, input_path: str):
        """
        Import learning data from JSON file
        
        Args:
            input_path: Path to input JSON file
        """
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Import patterns
        for pattern in data.get('patterns', []):
            cursor.execute("""
                INSERT OR REPLACE INTO learning_patterns (
                    pattern_id, auth_type, domain_pattern, success_rate,
                    usage_count, patterns, metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern['pattern_id'],
                pattern['auth_type'],
                pattern['domain_pattern'],
                pattern['success_rate'],
                pattern['usage_count'],
                json.dumps(pattern['patterns']),
                json.dumps(pattern.get('metadata', {})),
                pattern['created_at'],
                pattern['updated_at']
            ))
        
        conn.commit()
        conn.close()

"""
Extended Threat Analysis Methods

Helper methods for analyzing extended threat detection fields.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from shared_models.chunks import BehavioralChunk


class ExtendedThreatAnalysisMixin:
    """Mixin providing analysis methods for extended threat fields."""
    
    # Known malicious/suspicious patterns
    SUSPICIOUS_PROCESSES = {
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "psexec.exe", "mimikatz.exe", "procdump.exe", "net.exe",
        "netsh.exe", "sc.exe", "reg.exe", "wmic.exe",
    }
    
    SQL_INJECTION_PATTERNS = [
        "union select", "' or '1'='1", "'; drop table",
        "exec(", "xp_cmdshell", "information_schema",
    ]
    
    XSS_PATTERNS = [
        "<script>", "javascript:", "onerror=", "onload=",
        "<iframe", "<embed", "eval(", 
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        "../", "..\\", "%2e%2e", "....//", "..\\..\\"
    ]
    
    SUSPICIOUS_TLDs = [
        ".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".work",
    ]
    
    def _analyze_http_patterns(self, chunk: BehavioralChunk) -> dict:
        """Analyze HTTP-related fields for attack patterns."""
        http_methods = []
        status_codes = Counter()
        suspicious_uris = []
        user_agents = set()
        attack_indicators = []
        
        for event in chunk.events:
            # HTTP methods
            if event.http_method:
                http_methods.append(event.http_method)
            
            # Status codes
            if event.http_status:
                status_codes[str(event.http_status)] += 1
            
            # URI analysis for attacks
            if event.uri_path:
                uri_lower = event.uri_path.lower()
                
                # SQL injection
                for pattern in self.SQL_INJECTION_PATTERNS:
                    if pattern in uri_lower:
                        suspicious_uris.append(event.uri_path)
                        attack_indicators.append(f"SQL injection pattern: {pattern}")
                        break
                
                # XSS
                for pattern in self.XSS_PATTERNS:
                    if pattern in uri_lower:
                        suspicious_uris.append(event.uri_path)
                        attack_indicators.append(f"XSS pattern: {pattern}")
                        break
                
                # Path traversal
                for pattern in self.PATH_TRAVERSAL_PATTERNS:
                    if pattern in event.uri_path:
                        suspicious_uris.append(event.uri_path)
                        attack_indicators.append(f"Path traversal: {pattern}")
                        break
            
            # User agents
            if event.user_agent:
                user_agents.add(event.user_agent[:100])  # Truncate
        
        return {
            "methods": list(set(http_methods)) if http_methods else None,
            "status_codes": dict(status_codes) if status_codes else None,
            "suspicious_uris": suspicious_uris[:10] if suspicious_uris else None,  # Limit
            "user_agents": list(user_agents)[:5] if user_agents else None,  # Top 5
            "attack_indicators": list(set(attack_indicators)) if attack_indicators else None,
        }
    
    def _analyze_process_behavior(self, chunk: BehavioralChunk) -> dict:
        """Analyze process and endpoint behavior."""
        process_names = set()
        suspicious_processes = []
        command_patterns = []
        file_ops = Counter()
        registry_mods = []
        
        for event in chunk.events:
            # Process names
            if event.process_name:
                proc_name = event.process_name.lower()
                process_names.add(event.process_name)
                
                # Check against known suspicious processes
                if proc_name in self.SUSPICIOUS_PROCESSES:
                    suspicious_processes.append(event.process_name)
            
            # Command line analysis
            if event.command_line:
                cmd_lower = event.command_line.lower()
                # Detect suspicious commands
                if any(x in cmd_lower for x in ["encode", "bypass", "-enc", "iex", "downloadstring"]):
                    command_patterns.append(event.command_line[:200])  # Truncate
            
            # File operations
            if event.file_name:
                file_ops["file_access"] += 1
            
            # Registry modifications
            if event.registry_key:
                registry_mods.append(event.registry_key)
        
        return {
            "process_names": list(process_names)[:10] if process_names else None,
            "suspicious_processes": list(set(suspicious_processes)) if suspicious_processes else None,
            "command_patterns": command_patterns[:5] if command_patterns else None,
            "file_operations": dict(file_ops) if file_ops else None,
            "registry_mods": registry_mods[:5] if registry_mods else None,
        }
    
    def _analyze_geographic_patterns(self, chunk: BehavioralChunk) -> dict:
        """Analyze geographic patterns for anomalies."""
        countries = set()
        cities = []
        anomaly_detected = False
        anomaly_desc = None
        impossible_travel = False
        
        # Geographic analysis disabled (GeoIP removed for performance)
        # If GeoIP is re-enabled, uncomment the code below
        
        # # Blacklisted countries (example - customize per organization)
        # BLACKLISTED_COUNTRIES = {"KP", "IR", "SY"}  # North Korea, Iran, Syria
        # 
        # for event in chunk.events:
        #     if hasattr(event, 'geo_country') and event.geo_country:
        #         countries.add(event.geo_country)
        #         
        #         # Check blacklist
        #         if event.geo_country in BLACKLISTED_COUNTRIES:
        #             anomaly_detected = True
        #             anomaly_desc = f"Access from blacklisted country: {event.geo_country}"
        #     
        #     if hasattr(event, 'geo_city') and event.geo_city:
        #         cities.append((event.geo_city, event.timestamp))
        # 
        # # Detect impossible travel (same user from >1000km in <1 hour)
        # # Simplified: just check if multiple distant countries
        # if len(countries) > 2 and chunk.strategy.value == "user":
        #     impossible_travel = True
        
        return {
            "countries": None,  # GeoIP disabled
            "anomaly_detected": anomaly_detected,
            "anomaly_description": anomaly_desc,
            "impossible_travel": impossible_travel,
        }
    
    def _analyze_dns_patterns(self, chunk: BehavioralChunk) -> dict:
        """Analyze DNS queries for C2/tunneling/DGA."""
        queries = []
        suspicious_domains = []
        tunneling_indicators = []
        
        for event in chunk.events:
            if event.dns_query:
                queries.append(event.dns_query)
                
                # Check suspicious TLDs
                for tld in self.SUSPICIOUS_TLDs:
                    if event.dns_query.endswith(tld):
                        suspicious_domains.append(event.dns_query)
                        break
                
                # DGA detection (very long subdomain)
                parts = event.dns_query.split(".")
                if any(len(part) > 20 for part in parts):
                    suspicious_domains.append(event.dns_query)
                
                # DNS tunneling (excessive query length)
                if len(event.dns_query) > 100:
                    tunneling_indicators.append(f"Long query: {event.dns_query[:100]}")
        
        return {
            "queries": list(set(queries))[:10] if queries else None,
            "suspicious_domains": list(set(suspicious_domains)) if suspicious_domains else None,
            "tunneling_indicators": tunneling_indicators[:5] if tunneling_indicators else None,
        }
    
    def _analyze_email_patterns(self, chunk: BehavioralChunk) -> dict:
        """Analyze email patterns for phishing."""
        senders = set()
        suspicious_attachments = []
        phishing_indicators = []
        
        for event in chunk.events:
            if event.email_from:
                senders.add(event.email_from)
            
            if event.attachment_names:
                for attachment in event.attachment_names:
                    # Suspicious extensions
                    if any(attachment.endswith(ext) for ext in [".exe", ".scr", ".bat", ".vbs", ".js"]):
                        suspicious_attachments.append(attachment)
                        phishing_indicators.append(f"Suspicious attachment: {attachment}")
        
        return {
            "senders": list(senders)[:10] if senders else None,
            "suspicious_attachments": suspicious_attachments if suspicious_attachments else None,
            "phishing_indicators": phishing_indicators if phishing_indicators else None,
        }
    
    def _analyze_severity_distribution(self, chunk: BehavioralChunk) -> dict[str, int] | None:
        """Analyze severity distribution in chunk."""
        severity_counts = Counter()
        
        for event in chunk.events:
            if event.severity:
                severity_counts[event.severity] += 1
        
        return dict(severity_counts) if severity_counts else None
    
    def _analyze_session_patterns(self, chunk: BehavioralChunk) -> dict:
        """Analyze session patterns for anomalies."""
        sessions = set()
        anomalies = []
        
        for event in chunk.events:
            if event.session_id:
                sessions.add(event.session_id)
        
        # Simple anomaly: too many sessions for one entity
        if len(sessions) > 50:
            anomalies.append(f"Excessive sessions: {len(sessions)}")
        
        return {
            "unique_count": len(sessions),
            "anomalies": anomalies if anomalies else None,
        }

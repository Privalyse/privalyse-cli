"""JavaScript/TypeScript code analyzer for React form fields and privacy issues"""

import re
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from ..models.finding import Finding, ClassificationResult
from ..models.taint import DataFlowEdge
from .base_analyzer import BaseAnalyzer, AnalyzedSymbol, AnalyzedImport


class JSTaintTracker:
    """
    Tracks tainted variables in JavaScript code using regex-based analysis.
    Simulates AST-based taint tracking for "Lite" analysis.
    """
    def __init__(self):
        self.tainted_vars: Dict[str, Dict[str, Any]] = {} # name -> {pii_types: [], source: str}
        self.data_flow_edges: List[DataFlowEdge] = []

    def mark_tainted(self, name: str, pii_types: List[str], source: str, context: Optional[str] = None):
        """Mark a variable as tainted with specific PII types."""
        if not name or not pii_types:
            return
            
        if name not in self.tainted_vars:
            self.tainted_vars[name] = {'pii_types': [], 'source': source}
        
        # Add new PII types
        current_types = set(self.tainted_vars[name]['pii_types'])
        current_types.update(pii_types)
        self.tainted_vars[name]['pii_types'] = list(current_types)

    def add_edge(self, source: str, target: str, line: int, flow_type: str, transformation: Optional[str] = None, context: Optional[str] = None):
        """Add a data flow edge."""
        self.data_flow_edges.append(DataFlowEdge(
            source_var=source,
            target_var=target,
            source_line=line, # Simplified: assume source is near
            target_line=line,
            flow_type=flow_type,
            transformation=transformation,
            context=context
        ))

    def get_taint(self, name: str) -> Optional[Dict[str, Any]]:
        """Get taint info for a variable."""
        return self.tainted_vars.get(name)
        
    def is_tainted(self, name: str) -> bool:
        """Check if a variable is tainted."""
        return name in self.tainted_vars

    def infer_pii_type(self, var_name: str) -> List[str]:
        """Infer PII type from variable name."""
        var_lower = var_name.lower()
        pii_types = []
        
        # False Positive Reduction: Exclude config/service/handler objects
        if any(x in var_lower for x in ['config', 'service', 'handler', 'manager', 'factory', 'provider', 'module', 'controller', 'rules', 'context', 'schema']):
            return []
        
        if any(k in var_lower for k in ['email', 'e_mail', 'mail']):
            pii_types.append('email')
        if any(k in var_lower for k in ['password', 'passwd', 'pwd', 'secret', 'token', 'key', 'auth', 'credential', 'session_id', 'jwt', 'access_token', 'refresh_token', 'bearer']):
            pii_types.append('password')
        if any(k in var_lower for k in ['first_name', 'last_name', 'fullname', 'firstname', 'lastname', 'surname', 'family_name', 'display_name']):
            pii_types.append('name')
        if any(k in var_lower for k in ['user_id', 'customer_id', 'uuid', 'account_id', 'member_id']):
            pii_types.append('id')
        if any(k in var_lower for k in ['phone', 'mobile', 'tel', 'cell', 'fax']):
            pii_types.append('phone')
        if any(k in var_lower for k in ['address', 'city', 'country', 'zip', 'postal', 'street', 'state', 'province', 'geo', 'lat', 'lon']):
            pii_types.append('location')
        if any(k in var_lower for k in ['creditcard', 'credit_card', 'card_number', 'cc_number', 'cvv', 'iban', 'bank_account', 'routing_number', 'bic', 'swift']):
            pii_types.append('financial')
        if any(k in var_lower for k in ['ssn', 'social_security', 'tax_id', 'passport', 'driver_license', 'id_card', 'national_id']):
            pii_types.append('id')
        if any(k in var_lower for k in ['birth', 'dob', 'date_of_birth', 'birthday', 'age']):
            pii_types.append('birth_date')
            
        return pii_types


class JavaScriptAnalyzer(BaseAnalyzer):
    """Analyzes JavaScript/TypeScript code for privacy issues"""
    
    # React form field patterns for PII detection
    FORM_FIELD_PATTERNS = {
        "name": {
            "patterns": [
                r"\b(firstname|first[_-]?name|lastname|last[_-]?name|fullname|full[_-]?name|givenname|familyname|surname|displayname)\s*[:=]\s*",
            ],
            "severity": "medium",
            "category": "personal_data",
            "description": "Personal name field detected"
        },
        "password": {
            "patterns": [
                r"\b(password|pwd|passphrase|newPassword|oldPassword|confirmPassword|passwd)\s*[:=]\s*['\"]",
                r"\b(password|pwd|passphrase|newPassword|oldPassword|confirmPassword|passwd)\s*:\s*\{",
                r"type\s*=\s*['\"]password['\"]",
                r"name\s*=\s*['\"]password['\"]",
                r"placeholder\s*=\s*['\"].*(password|pwd|passphrase).*['\"]",
                r"label\s*=\s*['\"].*(password|pwd|passphrase).*['\"]",
                r"aria-label\s*=\s*['\"].*(password|pwd|passphrase).*['\"]",
            ],
            "severity": "high",
            "category": "credentials",
            "description": "Password field detected"
        },
        "email": {
            "patterns": [
                r"\b(email|emailAddress|userEmail|contactEmail|mail)\s*[:=]\s*['\"]",
                r"\b(email|emailAddress|userEmail|contactEmail|mail)\s*:\s*\{",
                r"type\s*=\s*['\"]email['\"]",
                r"name\s*=\s*['\"]email['\"]",
                r"placeholder\s*=\s*['\"].*(email|e-mail).*['\"]",
                r"label\s*=\s*['\"].*(email|e-mail).*['\"]",
                r"aria-label\s*=\s*['\"].*(email|e-mail).*['\"]",
            ],
            "severity": "medium",
            "category": "contact_data",
            "description": "Email address field detected"
        },
        "phone": {
            "patterns": [
                r"\b(phone|phoneNumber|mobile|telephone|contactNumber|tel)\s*[:=]\s*['\"]",
                r"\b(phone|phoneNumber|mobile|telephone|contactNumber|tel)\s*:\s*\{",
                r"type\s*=\s*['\"]tel['\"]",
                r"name\s*=\s*['\"](phone|mobile|tel).*['\"]",
                r"placeholder\s*=\s*['\"].*(phone|mobile|tel).*['\"]",
                r"label\s*=\s*['\"].*(phone|mobile|tel).*['\"]",
                r"aria-label\s*=\s*['\"].*(phone|mobile|tel).*['\"]",
            ],
            "severity": "medium",
            "category": "contact_data",
            "description": "Phone number field detected"
        },
        "business_data": {
            "patterns": [
                r"\b(organizationName|organization[_-]?name|companyName|company[_-]?name|orgName|company|organization|employer)\s*[:=]\s*['\"]",
                r"\b(organizationName|organization[_-]?name|companyName|company[_-]?name|orgName|company|organization|employer)\s*:\s*\{",
                r"name\s*=\s*['\"](company|organization|employer).*['\"]",
                r"placeholder\s*=\s*['\"].*(company|organization|employer).*['\"]",
                r"label\s*=\s*['\"].*(company|organization|employer).*['\"]",
                r"aria-label\s*=\s*['\"].*(company|organization|employer).*['\"]",
            ],
            "severity": "low",
            "category": "business_data",
            "description": "Organization/company field detected"
        },
        "location": {
            "patterns": [
                r"\b(address|street|streetAddress|city|zipCode|postalCode|postCode|country|state|province|location)\s*[:=]\s*['\"]",
                r"\b(address|street|streetAddress|city|zipCode|postalCode|postCode|country|state|province|location)\s*:\s*\{",
                r"name\s*=\s*['\"](address|street|city|zip|postal|country).*['\"]",
                r"placeholder\s*=\s*['\"].*(address|street|city|zip|postal|country).*['\"]",
                r"label\s*=\s*['\"].*(address|street|city|zip|postal|country).*['\"]",
                r"aria-label\s*=\s*['\"].*(address|street|city|zip|postal|country).*['\"]",
            ],
            "severity": "medium",
            "category": "location_data",
            "description": "Address/location field detected"
        },
        "financial": {
            "patterns": [
                r"\b(creditCard|credit[_-]?card|cardNumber|card[_-]?number|cvv|cvc|iban|account[_-]?number)\s*[:=]\s*['\"]",
                r"\b(creditCard|credit[_-]?card|cardNumber|card[_-]?number|cvv|cvc|iban|account[_-]?number)\s*:\s*\{",
                r"name\s*=\s*['\"](card|cc|cvv|iban|account).*['\"]",
                r"placeholder\s*=\s*['\"].*(card|cc|cvv|iban|account).*['\"]",
                r"label\s*=\s*['\"].*(card|cc|cvv|iban|account).*['\"]",
                r"aria-label\s*=\s*['\"].*(card|cc|cvv|iban|account).*['\"]",
            ],
            "severity": "high",
            "category": "financial_data",
            "description": "Financial data field detected"
        },
        "id": {
            "patterns": [
                r"\b(ssn|social[_-]?security|taxId|tax[_-]?id|nationalId|national[_-]?id|passport|driver[_-]?license)\s*[:=]\s*['\"]",
                r"\b(ssn|social[_-]?security|taxId|tax[_-]?id|nationalId|national[_-]?id|passport|driver[_-]?license)\s*:\s*\{",
                r"name\s*=\s*['\"](ssn|tax|passport|license).*['\"]",
                r"placeholder\s*=\s*['\"].*(ssn|tax|passport|license).*['\"]",
                r"label\s*=\s*['\"].*(ssn|tax|passport|license).*['\"]",
                r"aria-label\s*=\s*['\"].*(ssn|tax|passport|license).*['\"]",
            ],
            "severity": "high",
            "category": "identification",
            "description": "Government ID field detected"
        },
        "birth_date": {
            "patterns": [
                r"\b(birthDate|birth[_-]?date|dateOfBirth|date[_-]?of[_-]?birth|dob|birthday|birthYear|birth[_-]?year)\s*[:=]\s*['\"]",
                r"\b(birthDate|birth[_-]?date|dateOfBirth|date[_-]?of[_-]?birth|dob|birthday|birthYear|birth[_-]?year)\s*:\s*\{",
                r"name\s*=\s*['\"](birth|dob).*['\"]",
                r"placeholder\s*=\s*['\"].*(birth|dob).*['\"]",
                r"label\s*=\s*['\"].*(birth|dob).*['\"]",
                r"aria-label\s*=\s*['\"].*(birth|dob).*['\"]",
            ],
            "severity": "medium",
            "category": "personal_data",
            "description": "Birth date field detected"
        }
    }
    
    def __init__(self):
        self.taint_tracker = None
    
    def analyze_file(self, file_path: Path, code: str, consts: Dict = None, envmap: Dict = None, **kwargs) -> Tuple[List[Finding], List[Any]]:
        """
        Analyze a single file for privacy/security findings.
        Returns (findings, data_flows).
        """
        findings = []
        data_flows = []
        
        # Initialize taint tracker for this file
        self.taint_tracker = JSTaintTracker()
        
        # 1. Perform Lite Taint Analysis (Assignments & Propagation)
        taint_findings = self._perform_taint_analysis(file_path, code)
        findings.extend(taint_findings)
        
        # 2. Analyze React form fields
        findings.extend(self._analyze_form_fields(file_path, code))
        
        # 3. Analyze API calls and data transmission
        api_findings, api_flows = self._analyze_api_calls(file_path, code)
        findings.extend(api_findings)
        data_flows.extend(api_flows)
        
        # 4. Analyze localStorage/sessionStorage usage
        findings.extend(self._analyze_storage_usage(file_path, code))
        
        # 5. Analyze tracking scripts (cookies without consent risk)
        findings.extend(self._analyze_tracking_scripts(file_path, code))
        
        # 6. Analyze Backend Frameworks (Express/NestJS)
        findings.extend(self._analyze_backend_frameworks(file_path, code))
        
        # 7. Analyze Database Models (Mongoose/TypeORM)
        findings.extend(self._analyze_database_models(file_path, code))

        # 8. Analyze Infrastructure Security (Helmet, CORS, etc.)
        findings.extend(self._analyze_infra_security(file_path, code))
        
        # 9. Analyze Hardcoded Secrets
        findings.extend(self._analyze_secrets(file_path, code))
        
        # Return findings and collected data flow edges
        return findings, self.taint_tracker.data_flow_edges

    def _analyze_secrets(self, file_path: Path, code: str) -> List[Finding]:
        """
        Analyze code for hardcoded secrets (API keys, passwords, tokens).
        """
        findings = []
        lines = code.splitlines()
        
        # Patterns for variable names that suggest secrets
        secret_patterns = {
            'api_key': r'(api[_-]?key|apikey|api[_-]?token)',
            'password': r'(password|passwd|pwd)',
            'secret': r'(secret[_-]?key|client[_-]?secret|app[_-]?secret)',
            'token': r'(access[_-]?token|auth[_-]?token|bearer[_-]?token|refresh[_-]?token|id[_-]?token)',
            'aws': r'(aws[_-]?secret|aws[_-]?access|aws[_-]?key)',
            'private_key': r'(private[_-]?key|priv[_-]?key|rsa[_-]?key|dsa[_-]?key)',
            'database': r'(db[_-]?password|database[_-]?password|db[_-]?pass|connection[_-]?string|dsn)',
            'jwt': r'(jwt|json[_-]?web[_-]?token)',
        }
        
        # High-entropy string pattern (likely a secret)
        high_entropy_pattern = r'^[A-Za-z0-9+/=_-]{32,}$'
        
        # Regex to find assignments: const X = "Y", let X = 'Y', var X = "Y", key: "Y"
        assignment_regex = re.compile(r'(const|let|var|[\w]+)\s*[:=]\s*["\']([^"\']+)["\']')
        
        for i, line in enumerate(lines):
            # Skip comments
            if line.strip().startswith('//') or line.strip().startswith('*'):
                continue
                
            matches = assignment_regex.finditer(line)
            for match in matches:
                var_name = match.group(1).strip()
                # If it's a declaration like "const x", var_name is "const". We need the actual name.
                # The regex (const|let|var|[\w]+) captures the keyword OR the variable name if no keyword.
                # This is a bit loose. Let's refine.
                
                # Better regex for JS assignments
                # 1. const/let/var name = "value"
                # 2. name: "value" (object property)
                # 3. name = "value" (reassignment)
                pass # We will use a more specific loop below
        
        # Refined loop
        for i, line in enumerate(lines):
            if len(line) > 500: continue # Skip minified lines
            
            # Check for assignments
            # Group 1: Variable name
            # Group 2: Quote type
            # Group 3: Value
            assign_match = re.search(r'\b([a-zA-Z0-9_$]+)\s*[:=]\s*(["\'])(.*?)\2', line)
            if assign_match:
                var_name = assign_match.group(1)
                value = assign_match.group(3)
                
                # print(f"DEBUG: Analyzing {var_name} = {value}")
                
                # Check if it looks like a secret
                secret_type = None
                confidence = 0.0
                
                var_lower = var_name.lower()
                
                # Check variable name patterns
                for st, pattern in secret_patterns.items():
                    if re.search(pattern, var_lower, re.IGNORECASE):
                        if value and len(value) > 8:
                            if not value.lower() in ['your_api_key_here', 'changeme', 'secret', 'password', 'todo', 'placeholder']:
                                # Check for high entropy
                                if re.match(high_entropy_pattern, value):
                                    secret_type = st
                                    confidence = 1.0
                                else:
                                    secret_type = st
                                    confidence = 0.6
                                    # print(f"DEBUG: Matched {st} with confidence 0.6")
                                break
                
                # Check for high-entropy strings regardless of name
                if not secret_type and re.match(high_entropy_pattern, value) and len(value) >= 32:
                    secret_type = 'token'
                    confidence = 0.9
                    # print(f"DEBUG: Matched token with confidence 0.9")
                
                if secret_type:
                    findings.append(Finding(
                        rule="HARDCODED_SECRET",
                        severity="critical" if confidence > 0.8 else "high",
                        file=str(file_path),
                        line=i + 1,
                        snippet=f'{var_name} = "***"',
                        classification=ClassificationResult(
                            pii_types=[secret_type, 'credentials'],
                            sectors=['security', 'authentication'],
                            severity='critical' if confidence > 0.8 else 'high',
                            article='Art. 32',
                            legal_basis_required=True,
                            category='credentials',
                            confidence=confidence,
                            reasoning=f"Hardcoded {secret_type} detected in variable '{var_name}'",
                            gdpr_articles=["Art. 32"]
                        )
                    ))
                    
        return findings

    def _analyze_infra_security(self, file_path: Path, code: str) -> List[Finding]:
        """
        Analyze infrastructure security configuration (Express, Helmet, CORS).
        """
        findings = []
        lines = code.splitlines()
        
        # Check if it's an Express app file
        is_express = "express" in code and ("require" in code or "import" in code)
        if not is_express:
            return findings

        has_helmet = False
        has_cors = False
        has_disable_x_powered_by = False
        
        # Simple check for usage
        for line in lines:
            if "helmet" in line and ("use" in line or "require" in line or "import" in line):
                has_helmet = True
            if "cors" in line and ("use" in line or "require" in line or "import" in line):
                has_cors = True
            if "disable" in line and "x-powered-by" in line.lower():
                has_disable_x_powered_by = True
                
        # If it looks like the main server file (app.listen or const app = express())
        if "app.listen" in code or "const app = express()" in code:
            pass
            # REMOVED: INFRA_EXPRESS_HELMET_MISSING - Focus on PII protection only
            # if not has_helmet:
            #     findings.append(Finding(
            #         rule="INFRA_EXPRESS_HELMET_MISSING",
            #         severity="medium",
            #         file=str(file_path),
            #         line=1, # General file finding
            #         snippet="const app = express();",
            #         classification=ClassificationResult(
            #             pii_types=[],
            #             category="security_misconfiguration",
            #             severity="medium",
            #             confidence=0.9,
            #             reasoning="Express application missing Helmet middleware (Security Headers)",
            #             sectors=[],
            #             article="Art. 32",
            #             legal_basis_required=True
            #         )
            #     ))
            
            # REMOVED: INFRA_EXPRESS_FINGERPRINT - Focus on PII protection only
            # if not has_disable_x_powered_by and not has_helmet: 
            #     findings.append(Finding(
            #         rule="INFRA_EXPRESS_FINGERPRINT",
            #         severity="low",
            #         file=str(file_path),
            #         line=1,
            #         snippet="const app = express();",
            #         classification=ClassificationResult(
            #             pii_types=[],
            #             category="security_misconfiguration",
            #             severity="low",
            #             confidence=0.9,
            #             reasoning="Server fingerprinting enabled (X-Powered-By header not disabled)",
            #             sectors=[],
            #             article="Art. 32",
            #             legal_basis_required=True
            #         )
            #     ))

        return findings

    def _perform_taint_analysis(self, file_path: Path, code: str) -> List[Finding]:
        """
        Perform 'Lite' taint analysis using regex to track variable assignments and usage.
        Supports multiline sinks and state tracking.
        """
        findings = []
        lines = code.splitlines()
        
        # Regex patterns
        assign_pattern = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(.+?)(?:;)?$")
        destruct_pattern = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+\{([^}]+)\}\s*=\s*(.+?)(?:;)?$")
        func_arg_pattern = re.compile(r"(?:function\s+\w*|\(?)\s*\(([^)]+)\)\s*(?:=>|\{)")
        usestate_pattern = re.compile(r"const\s+\[([a-zA-Z0-9_$]+),\s*[a-zA-Z0-9_$]+\]\s*=\s*useState")
        
        # Sink Start: Detects start of a sink call
        sink_start_pattern = re.compile(r"(console\.(?:log|info|warn|error)|logger\.\w+|fetch|axios\.\w+|res\.(?:json|send)|[A-Z]\w*\.(?:create|insert|save|update|updateOne|updateMany))\s*\(")
        
        # DB Return: const user = await User.create(...)
        db_return_pattern = re.compile(r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:await\s+)?[A-Z]\w*\.(?:create|insert|save|findOne|findById)")

        # Sanitization functions
        sanitization_pattern = re.compile(r"(hash|encrypt|mask|sanitize|anonymize)", re.IGNORECASE)

        current_sink = None
        current_sink_url = None
        
        for i, line in enumerate(lines):
            line_num = i + 1
            line_stripped = line.strip()
            
            # 1. Assignments
            if match := assign_pattern.search(line_stripped):
                lhs_var = match.group(1)
                rhs_expr = match.group(2)
                
                # Check for sanitization
                is_sanitized = bool(sanitization_pattern.search(rhs_expr))
                
                pii_types = self.taint_tracker.infer_pii_type(lhs_var)
                if pii_types and not is_sanitized:
                    self.taint_tracker.mark_tainted(lhs_var, pii_types, f"Variable name '{lhs_var}'")
                
                rhs_clean = rhs_expr.strip().rstrip(';')
                taint_info = self.taint_tracker.get_taint(rhs_clean)
                if taint_info:
                    if is_sanitized:
                        # If sanitized, we don't propagate the taint (or we could mark it as safe)
                        pass 
                    else:
                        self.taint_tracker.mark_tainted(lhs_var, taint_info['pii_types'], f"Assigned from '{rhs_clean}'")

            # 2. Destructuring
            if match := destruct_pattern.search(line_stripped):
                vars_str = match.group(1)
                rhs_expr = match.group(2).strip().rstrip(';')
                rhs_is_source = 'req.body' in rhs_expr or 'req.query' in rhs_expr
                vars_list = [v.strip().split(':')[0].strip() for v in vars_str.split(',')]
                for var_name in vars_list:
                    pii_types = self.taint_tracker.infer_pii_type(var_name)
                    if pii_types:
                        source_desc = f"Destructured variable '{var_name}'"
                        if rhs_is_source:
                            source_desc += f" from '{rhs_expr}'"
                        self.taint_tracker.mark_tainted(var_name, pii_types, source_desc)
                        
                        # Capture route for graph linking if this is an Express handler
                        # Heuristic: look backwards for app.post/get/put/delete
                        if rhs_is_source:
                            route = None
                            # Look back up to 20 lines
                            for j in range(max(0, i-20), i):
                                route_match = re.search(r"app\.(post|get|put|delete)\s*\(\s*['\"]([^'\"]+)['\"]", lines[j])
                                if route_match:
                                    route = route_match.group(2)
                                    break
                            
                            if route:
                                # Add metadata to the taint source for graph linking
                                if var_name in self.taint_tracker.tainted_vars:
                                    self.taint_tracker.tainted_vars[var_name]['route'] = route

            # 3. Function Args
            if match := func_arg_pattern.search(line_stripped):
                args_str = match.group(1)
                args = [a.strip().split(':')[0].strip() for a in args_str.split(',')]
                for arg in args:
                    pii_types = self.taint_tracker.infer_pii_type(arg)
                    if pii_types:
                        self.taint_tracker.mark_tainted(arg, pii_types, f"Function argument '{arg}'")

            # 4. React useState
            if match := usestate_pattern.search(line_stripped):
                state_var = match.group(1)
                pii_types = self.taint_tracker.infer_pii_type(state_var)
                if pii_types:
                    self.taint_tracker.mark_tainted(state_var, pii_types, f"React state '{state_var}'")
            
            # 5. DB Return Value Propagation
            if match := db_return_pattern.search(line_stripped):
                lhs_var = match.group(1)
                # Assume DB objects contain PII
                self.taint_tracker.mark_tainted(lhs_var, ["database_record"], f"Database record from '{match.group(0)}'")

            # 6. Sink Detection (Multiline State Machine)
            if match := sink_start_pattern.search(line_stripped):
                current_sink = match.group(1)
                # Extract URL for network sinks
                if 'axios' in current_sink or 'fetch' in current_sink:
                    url_match = re.search(r"['\"]([^'\"]+)['\"]", line_stripped)
                    if url_match:
                        current_sink_url = url_match.group(1)
                    else:
                        current_sink_url = None
                else:
                    current_sink_url = None
            
            if current_sink:
                # Handle template literals: keep only the interpolated parts
                # Regex to find backtick strings
                def replace_template(match):
                    content = match.group(1)
                    # Extract variables from ${...}
                    vars_found = re.findall(r'\$\{([^}]+)\}', content)
                    return " " + " ".join(vars_found) + " "

                # Replace `...` with just the variables inside
                line_no_templates = re.sub(r'`([^`]*)`', replace_template, line_stripped)

                # False Positive Reduction: Remove string literals before checking for variables
                # Replace "..." and '...' with empty strings
                line_no_strings = re.sub(r'([\'"])(?:(?=(\\?))\2.)*?\1', '', line_no_templates)
                
                # Extract potential variable names (words) from the string-free line
                words = re.findall(r"[a-zA-Z0-9_$]+", line_no_strings)
                
                for word in words:
                    if self.taint_tracker.is_tainted(word):
                        # Avoid flagging the sink name itself or keywords
                        if word == current_sink or word in ['const', 'let', 'var', 'await', 'async', 'return']:
                            continue
                            
                        taint_info = self.taint_tracker.get_taint(word)
                        
                        # Add Data Flow Edge
                        self.taint_tracker.add_edge(
                            source=word,
                            target=current_sink,
                            line=line_num,
                            flow_type="sink",
                            context=f"URL: {current_sink_url}" if current_sink_url else None
                        )
                        
                        # Determine rule
                        rule = "JS_DATA_LEAK"
                        if "res." in current_sink:
                            rule = "API_RESPONSE_LEAK"
                        elif any(x in current_sink for x in ["create", "insert", "save", "update"]):
                            rule = "DB_WRITE_PII"
                        
                        finding = Finding(
                            rule=rule,
                            severity="high",
                            file=str(file_path),
                            line=line_num,
                            snippet=line.strip()[:200],
                            classification=ClassificationResult(
                                pii_types=taint_info['pii_types'],
                                category="data_leak",
                                severity="high",
                                confidence=0.85,
                                reasoning=f"Tainted variable '{word}' passed to sink '{current_sink}'",
                                sectors=[],
                                article="Art. 6",
                                legal_basis_required=True
                            ),
                            tainted_variables=[word],
                            taint_sources=[taint_info['source']],
                            flow_path=[taint_info['source'], word, current_sink] if current_sink else [taint_info['source'], word]
                        )
                        findings.append(finding)
                
                # Check for end of sink call
                if ");" in line_stripped or (line_stripped.strip().endswith(")") and "{" not in line_stripped):
                    current_sink = None
                    
        return findings

    def _analyze_backend_frameworks(self, file_path: Path, code: str) -> List[Finding]:
        """
        Analyze Node.js backend frameworks (Express, NestJS) for PII handling.
        """
        findings = []
        lines = code.splitlines()
        
        # Express: req.body.email, req.query.password, req.ip
        express_access_pattern = re.compile(r"req\.(body|query|params)\.([a-zA-Z0-9_$]+)")
        express_ip_pattern = re.compile(r"req\.(ip|ips)\b")
        
        # NestJS: @Body() email: string, @Query('password')
        nest_body_pattern = re.compile(r"@Body\s*\(\s*(?:['\"]([^'\"]+)['\"])?\s*\)\s*([a-zA-Z0-9_$]+)")
        nest_query_pattern = re.compile(r"@Query\s*\(\s*(?:['\"]([^'\"]+)['\"])?\s*\)\s*([a-zA-Z0-9_$]+)")
        
        for i, line in enumerate(lines):
            line_num = i + 1
            line_stripped = line.strip()
            
            # 1. Express Request Access
            if match := express_access_pattern.search(line_stripped):
                source_type = match.group(1) # body, query, params
                field_name = match.group(2)
                
                pii_types = self.taint_tracker.infer_pii_type(field_name)
                if pii_types:
                    # Mark as tainted for subsequent analysis
                    full_var = f"req.{source_type}.{field_name}"
                    self.taint_tracker.mark_tainted(full_var, pii_types, f"Express request {source_type}")
                    
                    # Also create a finding for "Unvalidated PII Input"
                    finding = Finding(
                        rule="BACKEND_PII_INPUT",
                        severity="medium",
                        file=str(file_path),
                        line=line_num,
                        snippet=line.strip()[:200],
                        classification=ClassificationResult(
                            pii_types=pii_types,
                            category="input_data",
                            severity="medium",
                            confidence=0.9,
                            reasoning=f"PII field '{field_name}' accessed from request {source_type}",
                            sectors=[],
                            article="Art. 6",
                            legal_basis_required=True
                        )
                    )
                    findings.append(finding)

            # 2. Express IP Address (Online Identifier)
            if match := express_ip_pattern.search(line_stripped):
                finding = Finding(
                    rule="BACKEND_PII_INPUT",
                    severity="medium",
                    file=str(file_path),
                    line=line_num,
                    snippet=line.strip()[:200],
                    classification=ClassificationResult(
                        pii_types=["online_identifier"],
                        category="input_data",
                        severity="medium",
                        confidence=0.95,
                        reasoning="IP address accessed from request (Online Identifier)",
                        sectors=[],
                        article="Art. 6",
                        legal_basis_required=True
                    )
                )
                findings.append(finding)

            # 3. NestJS Decorators
            for pattern, source_name in [(nest_body_pattern, "Body"), (nest_query_pattern, "Query")]:
                if match := pattern.search(line_stripped):
                    # Group 1 is optional name in decorator, Group 2 is variable name
                    decorator_arg = match.group(1)
                    var_name = match.group(2)
                    
                    target_name = decorator_arg if decorator_arg else var_name
                    pii_types = self.taint_tracker.infer_pii_type(target_name)
                    
                    if pii_types:
                        self.taint_tracker.mark_tainted(var_name, pii_types, f"NestJS @{source_name}")
                        
                        finding = Finding(
                            rule="BACKEND_PII_INPUT",
                            severity="medium",
                            file=str(file_path),
                            line=line_num,
                            snippet=line.strip()[:200],
                            classification=ClassificationResult(
                                pii_types=pii_types,
                                category="input_data",
                                severity="medium",
                                confidence=0.9,
                                reasoning=f"PII field '{target_name}' received via @{source_name}",
                                sectors=[],
                                article="Art. 6",
                                legal_basis_required=True
                            )
                        )
                        findings.append(finding)
                        
        return findings

    def _analyze_database_models(self, file_path: Path, code: str) -> List[Finding]:
        """
        Analyze Database Models (Mongoose, TypeORM, Sequelize) for PII definitions.
        """
        findings = []
        lines = code.splitlines()
        
        # Mongoose: email: { type: String } or email: String
        mongoose_field_pattern = re.compile(r"([a-zA-Z0-9_$]+)\s*:\s*(?:\{.*?type:\s*String|String)")
        
        # TypeORM/Sequelize: @Column() email: string
        orm_column_pattern = re.compile(r"@Column\s*\(.*?\)\s*([a-zA-Z0-9_$]+)")
        
        for i, line in enumerate(lines):
            line_num = i + 1
            line_stripped = line.strip()
            
            # Check Mongoose Fields
            if match := mongoose_field_pattern.search(line_stripped):
                field_name = match.group(1)
                pii_types = self.taint_tracker.infer_pii_type(field_name)
                
                if pii_types:
                    finding = Finding(
                        rule="DB_MODEL_PII",
                        severity="medium",
                        file=str(file_path),
                        line=line_num,
                        snippet=line.strip()[:200],
                        classification=ClassificationResult(
                            pii_types=pii_types,
                            category="stored_data",
                            severity="medium",
                            confidence=0.95,
                            reasoning=f"Database model defines PII field '{field_name}'",
                            sectors=[],
                            article="Art. 6",
                            legal_basis_required=True
                        ),
                        # Add flow path to prevent "Unknown Source"
                        flow_path=["Data Model (Schema)", field_name, "Database"]
                    )
                    findings.append(finding)

            # Check TypeORM/Sequelize Columns
            if match := orm_column_pattern.search(line_stripped):
                field_name = match.group(1)
                pii_types = self.taint_tracker.infer_pii_type(field_name)
                
                if pii_types:
                    finding = Finding(
                        rule="DB_MODEL_PII",
                        severity="medium",
                        file=str(file_path),
                        line=line_num,
                        snippet=line.strip()[:200],
                        classification=ClassificationResult(
                            pii_types=pii_types,
                            category="stored_data",
                            severity="medium",
                            confidence=0.95,
                            reasoning=f"ORM Entity defines PII field '{field_name}'",
                            sectors=[],
                            article="Art. 6",
                            legal_basis_required=True
                        ),
                        # Add flow path to prevent "Unknown Source"
                        flow_path=["Data Model (Entity)", field_name, "Database"]
                    )
                    findings.append(finding)
                    
        return findings

    def extract_symbols(self, code: str) -> List[AnalyzedSymbol]:
        """
        Extract JS/TS functions and classes for the Symbol Table.
        Uses regex heuristics since we don't have a full JS parser.
        """
        symbols = []
        lines = code.splitlines()
        
        # Regex for function definitions: function myFunc(), const myFunc = () =>, class MyClass
        func_pattern = re.compile(r"(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_]+)\s*\(")
        arrow_pattern = re.compile(r"(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(?:async\s*)?\(?.*?\)?\s*=>")
        class_pattern = re.compile(r"(?:export\s+)?class\s+([a-zA-Z0-9_]+)")
        
        for i, line in enumerate(lines):
            # Functions
            if match := func_pattern.search(line):
                symbols.append(AnalyzedSymbol(
                    name=match.group(1),
                    type='function',
                    line=i + 1,
                    is_exported='export' in line,
                    signature=line.strip()
                ))
            # Arrow functions
            elif match := arrow_pattern.search(line):
                symbols.append(AnalyzedSymbol(
                    name=match.group(1),
                    type='function',
                    line=i + 1,
                    is_exported='export' in line,
                    signature=line.strip()
                ))
            # Classes
            elif match := class_pattern.search(line):
                symbols.append(AnalyzedSymbol(
                    name=match.group(1),
                    type='class',
                    line=i + 1,
                    is_exported='export' in line,
                    signature=line.strip()
                ))
                
        return symbols

    def extract_imports(self, code: str) -> List[AnalyzedImport]:
        """
        Extract JS/TS imports for the Dependency Graph.
        Supports ES6 imports and CommonJS require.
        """
        imports = []
        lines = code.splitlines()
        
        # ES6: import { X } from 'y'; import X from 'y';
        import_pattern = re.compile(r"import\s+(?:\{?[\s\w,]+\}?|\*\s+as\s+\w+)\s+from\s+['\"]([^'\"]+)['\"]")
        # CommonJS: const X = require('y');
        require_pattern = re.compile(r"(?:const|let|var)\s+(?:\{?[\s\w,]+\}?|\w+)\s*=\s*require\(['\"]([^'\"]+)['\"]\)")
        
        for i, line in enumerate(lines):
            if match := import_pattern.search(line):
                imports.append(AnalyzedImport(
                    source_module=match.group(1),
                    imported_names=[], # Parsing names is complex with regex, keeping simple for now
                    line=i + 1
                ))
            elif match := require_pattern.search(line):
                imports.append(AnalyzedImport(
                    source_module=match.group(1),
                    imported_names=[],
                    line=i + 1
                ))
                
        return imports
    
    def _analyze_tracking_scripts(self, file_path: Path, code: str) -> List[Finding]:
        """Detect third-party tracking scripts that require consent"""
        findings = []
        lines = code.splitlines()
        
        tracking_patterns = {
            "GOOGLE_ANALYTICS": {
                "pattern": re.compile(r"\b(ga\('create'|gtag\('config'|googletagmanager\b)"),
                "desc": "Google Analytics/Tag Manager detected"
            },
            "FACEBOOK_PIXEL": {
                "pattern": re.compile(r"\bfbq\('init'"),
                "desc": "Facebook Pixel detected"
            },
            "MIXPANEL": {
                "pattern": re.compile(r"\bmixpanel\.init\b"),
                "desc": "Mixpanel analytics detected"
            },
            "HOTJAR": {
                "pattern": re.compile(r"\bhj\('identify'"),
                "desc": "Hotjar recording detected"
            },
            "SEGMENT": {
                "pattern": re.compile(r"\banalytics\.load\b"),
                "desc": "Segment analytics detected"
            }
        }
        
        for line_num, line in enumerate(lines, start=1):
            for rule_name, config in tracking_patterns.items():
                if config["pattern"].search(line):
                    # Heuristic: Check for consent checks in previous lines
                    # Look back up to 5 lines for "if" and "consent/cookie/allowed"
                    has_consent_check = False
                    start_check = max(0, line_num - 6)
                    context_lines = lines[start_check:line_num-1]
                    
                    consent_pattern = re.compile(r"if\s*\(.*(consent|accepted|allowed|cookie|banner|agreed)", re.IGNORECASE)
                    
                    for ctx_line in context_lines:
                        if consent_pattern.search(ctx_line):
                            has_consent_check = True
                            break
                    
                    severity = "medium"
                    reasoning = f"{config['desc']}. Ensure this is loaded only AFTER explicit user consent (GDPR/ePrivacy)."
                    
                    if has_consent_check:
                        severity = "low"
                        reasoning = f"{config['desc']} detected inside a potential consent check. Verify logic manually."

                    finding = Finding(
                        rule=f"TRACKING_{rule_name}",
                        severity=severity,
                        file=str(file_path),
                        line=line_num,
                        snippet=line.strip()[:200],
                        classification=ClassificationResult(
                            pii_types=["tracking_data", "online_identifiers"],
                            sectors=["marketing"],
                            severity=severity,
                            article="Art. 6 / ePrivacy",
                            legal_basis_required=True,
                            category="tracking",
                            confidence=0.95 if not has_consent_check else 0.6,
                            reasoning=reasoning
                        )
                    )
                    findings.append(finding)
        
        return findings

    def _analyze_form_fields(self, file_path: Path, code: str) -> List[Finding]:
        """Detect React form fields that collect PII"""
        findings = []
        lines = code.splitlines()
        
        # Pre-compile all patterns once for efficiency
        compiled_patterns = {}
        for pii_type, config in self.FORM_FIELD_PATTERNS.items():
            compiled_patterns[pii_type] = {
                'patterns': [re.compile(p, re.IGNORECASE) for p in config["patterns"]],
                'config': config
            }
        
        # Iterate through lines once, check all patterns (allow multiple PII types per line)
        for line_num, line in enumerate(lines, start=1):
            for pii_type, data in compiled_patterns.items():
                config = data['config']
                
                # Try all patterns for this PII type until one matches
                for pattern in data['patterns']:
                    match = pattern.search(line)
                    if match:
                        # If the pattern has a group, use it as the field name, otherwise use the PII type
                        field_name = match.group(1) if match.lastindex and match.lastindex >= 1 else pii_type
                        
                        # Define source based on context (Form Input)
                        source_node = "User Input (Form)"
                        
                        finding = Finding(
                            rule=f"FORM_FIELD_{pii_type.upper()}",
                            severity=config["severity"],
                            file=str(file_path),
                            line=line_num,
                            snippet=line.strip()[:200],
                            classification=ClassificationResult(
                                pii_types=[pii_type],
                                category=config["category"],
                                severity=config["severity"],
                                confidence=0.9,
                                article="Art. 6",
                                legal_basis_required=True,
                                sectors=[],
                                reasoning=config["description"]
                            ),
                            # Add flow path to prevent "Unknown Source"
                            flow_path=[source_node, field_name, "Form State"]
                        )
                        findings.append(finding)
                        break  # Found match for this PII type, try next PII type (allows multiple per line)
        
        return findings
    
    def _analyze_api_calls(self, file_path: Path, code: str) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        """Analyze fetch() and axios calls for data transmission"""
        findings = []
        data_flows = []
        lines = code.splitlines()
        
        # Detect fetch() calls
        fetch_pattern = re.compile(r"\bfetch\s*\(\s*['\"]([^'\"]+)['\"]")
        axios_pattern = re.compile(r"\baxios\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]")
        
        for line_num, line in enumerate(lines, start=1):
            # Check for fetch calls
            fetch_match = fetch_pattern.search(line)
            if fetch_match:
                url = fetch_match.group(1)
                is_secure = url.startswith("https://")
                
                if not is_secure and (url.startswith("http://") or url.startswith("/")):
                    finding = Finding(
                        rule="HTTP_INSECURE_API",
                        severity="high",
                        file=str(file_path),
                        line=line_num,
                        snippet=line.strip()[:200],
                        classification=ClassificationResult(
                            pii_types=["network"],
                            category="security",
                            severity="high",
                            confidence=0.95,
                            sectors=[],
                            article=None,
                            legal_basis_required=False,
                            reasoning="Insecure HTTP API call"
                        )
                    )
                    findings.append(finding)
                
                data_flows.append({
                    "type": "network",
                    "library": "fetch",
                    "url": url,
                    "secure": is_secure,
                    "file": str(file_path),
                    "line": line_num
                })
            
            # Check for axios calls
            axios_match = axios_pattern.search(line)
            if axios_match:
                method = axios_match.group(1).upper()
                url = axios_match.group(2)
                is_secure = url.startswith("https://")
                
                if not is_secure and (url.startswith("http://") or url.startswith("/")):
                    finding = Finding(
                        rule="HTTP_INSECURE_API",
                        severity="high",
                        file=str(file_path),
                        line=line_num,
                        snippet=line.strip()[:200],
                        classification=ClassificationResult(
                            pii_types=["network"],
                            category="security",
                            severity="high",
                            confidence=0.95,
                            sectors=[],
                            article=None,
                            legal_basis_required=False,
                            reasoning="Insecure HTTP API call"
                        )
                    )
                    findings.append(finding)
                
                data_flows.append({
                    "type": "network",
                    "library": "axios",
                    "method": method,
                    "url": url,
                    "secure": is_secure,
                    "file": str(file_path),
                    "line": line_num
                })
        
        return findings, data_flows
    
    def _analyze_storage_usage(self, file_path: Path, code: str) -> List[Finding]:
        """Detect localStorage/sessionStorage usage with sensitive data"""
        findings = []
        lines = code.splitlines()
        
        storage_pattern = re.compile(r"\b(localStorage|sessionStorage)\.setItem\s*\(")
        token_pattern = re.compile(r"(token|jwt|session|auth|password|secret)", re.IGNORECASE)
        
        for line_num, line in enumerate(lines, start=1):
            if storage_pattern.search(line) and token_pattern.search(line):
                finding = Finding(
                    rule="BROWSER_TOKEN_STORAGE",
                    severity="high",
                    file=str(file_path),
                    line=line_num,
                    snippet=line.strip()[:200],
                    classification=ClassificationResult(
                        pii_types=["token"],
                        category="credentials",
                        severity="high",
                        confidence=0.85,
                        article="Art. 6",
                        legal_basis_required=True,
                        sectors=[],
                        reasoning="Sensitive data in browser storage"
                    )
                )
                findings.append(finding)
        
        return findings

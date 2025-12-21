"""Taint tracking data models and tracker implementation"""

import ast
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class TaintInfo:
    """Information about tainted (PII-containing) variables"""
    variable_name: str
    pii_types: List[str]
    source_line: int
    source_node: str  # AST node type that introduced taint
    taint_source: Optional[str] = None  # Where did the taint come from?
    confidence: float = 1.0
    transformations: List[str] = field(default_factory=list)
    context: Optional[str] = None  # Context where taint was introduced (e.g. function name)
    flow_path: List[str] = field(default_factory=list)  # Sequence of nodes/vars in the flow
    is_sanitized: bool = False  # True if data has passed through a sanitization function
    sources: List[str] = field(default_factory=list) # Multiple sources support

    def __post_init__(self):
        if self.taint_source and not self.sources:
            self.sources = [self.taint_source]
        elif self.sources and not self.taint_source:
            self.taint_source = self.sources[0]


@dataclass
class DataFlowEdge:
    """Represents data flowing from source to target"""
    source_var: str
    target_var: str
    source_line: int
    target_line: int
    flow_type: str  # "assignment", "attribute", "call", "return"
    transformation: Optional[str] = None
    context: Optional[str] = None  # Context of the flow (e.g. function name)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_var": self.source_var,
            "target_var": self.target_var,
            "source_line": self.source_line,
            "target_line": self.target_line,
            "flow_type": self.flow_type,
            "transformation": self.transformation,
            "context": self.context
        }


class TaintTracker:
    """
    Tracks tainted variables through a single file using AST analysis.
    Implements intra-procedural taint analysis.
    """
    
    def __init__(self):
        self.tainted_vars: Dict[str, TaintInfo] = {}
        self.data_flow_edges: List[DataFlowEdge] = []
        self.function_params: Dict[str, List[str]] = {}  # function_name -> param names
        # DB column mapping for tracking PII storage
        self.db_column_mapping: Dict[str, Dict[str, Any]] = {}  # column_name -> {source_var, pii_types, table}
    
    def is_tainted(self, node: ast.AST) -> bool:
        """Check if an AST node represents a tainted value"""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.Attribute):
            return self.is_tainted_attribute(node)
        elif isinstance(node, ast.Subscript):
            return self.is_tainted(node.value)
        return False
    
    def is_tainted_attribute(self, node: ast.Attribute) -> bool:
        """Check if attribute access refers to tainted data"""
        # Check if base object is tainted
        if isinstance(node.value, ast.Name):
            base_var = node.value.id
            if base_var in self.tainted_vars:
                return True
        
        # Check if attribute name suggests PII
        attr_name = node.attr.lower()
        pii_indicators = ['email', 'password', 'token', 'ssn', 'phone', 'address',
                         'first_name', 'last_name', 'user_id', 'customer_id']
        return any(indicator in attr_name for indicator in pii_indicators)
    
    def get_taint_info(self, node: ast.AST) -> Optional[TaintInfo]:
        """Get taint information for a node"""
        if isinstance(node, ast.Name):
            return self.tainted_vars.get(node.id)
        return None

    def get_taint(self, var_name: str) -> Optional[TaintInfo]:
        """Get taint information for a variable name (string)"""
        return self.tainted_vars.get(var_name)
    
    def infer_pii_type(self, var_name: str, context: str = "") -> List[str]:
        """Infer PII type from variable name and context"""
        var_lower = var_name.lower()
        context_lower = context.lower()
        combined = f"{var_lower} {context_lower}"
        
        pii_types = []
        
        # Email
        if any(k in combined for k in ['email', 'e_mail', 'mail']):
            pii_types.append('email')
        
        # Password/Secrets
        if any(k in combined for k in ['password', 'passwd', 'pwd', 'secret', 'token', 'key', 'auth', 'credential', 'session_id', 'jwt', 'access_token', 'refresh_token', 'bearer']):
            pii_types.append('password')
        
        # Names
        if any(k in combined for k in ['first_name', 'last_name', 'name', 'fullname', 'firstname', 'lastname', 'surname', 'family_name']):
            pii_types.append('name')
        
        # IDs
        if any(k in combined for k in ['user_id', 'customer_id', 'id', 'uuid', 'account_id', 'member_id']):
            pii_types.append('id')
        
        # Phone
        if any(k in combined for k in ['phone', 'mobile', 'tel', 'telephone', 'cell', 'fax']):
            pii_types.append('phone')
        
        # Location
        if any(k in combined for k in ['address', 'location', 'latitude', 'longitude', 'gps', 'geo', 'city', 'country', 'zip', 'postal', 'state', 'province']):
            pii_types.append('location')
        
        # SSN / National IDs
        if any(k in combined for k in ['ssn', 'social_security', 'national_id', 'tax_id', 'insurance_number', 'passport', 'driver_license', 'id_card']):
            pii_types.append('ssn')
        
        # Financial (enhanced patterns)
        if any(k in combined for k in ['credit_card', 'card_number', 'cc', 'cvv', 'iban', 'account_number', 'bank', 'credit', 'card', 'routing_number', 'bic', 'swift']):
            pii_types.append('financial')
        
        # Birth Date / Age
        if any(k in combined for k in ['birth', 'dob', 'date_of_birth', 'birthday', 'age']):
            pii_types.append('birth_date')
        
        # IP Address
        if any(k in combined for k in ['ip_address', 'remote_addr', 'client_ip', 'ip']):
            pii_types.append('ip_address')
        
        # Special Category Data (Art. 9 GDPR)
        # Biometric
        if any(k in combined for k in ['biometric', 'fingerprint', 'face', 'face_encoding', 'facial']):
            pii_types.append('biometric')
        
        # Health
        if any(k in combined for k in ['health', 'medical', 'diagnosis', 'medication', 'blood', 'hospital']):
            pii_types.append('health')
        
        # Racial/Ethnic Origin
        if any(k in combined for k in ['race', 'ethnic', 'ethnicity', 'religion', 'religious']):
            pii_types.append('racial_ethnic')
        
        # Gender
        if any(k in combined for k in ['gender', 'sex']):
            pii_types.append('gender')
        
        # Biometric
        if any(k in combined for k in ['fingerprint', 'face', 'biometric', 'retina', 'iris']):
            pii_types.append('biometric')
        
        # Health
        if any(k in combined for k in ['diagnosis', 'medication', 'blood_type', 'medical', 'health']):
            pii_types.append('health')
        
        # Demographic (Art. 9 GDPR)
        if any(k in combined for k in ['ethnicity', 'race', 'religion', 'political', 'sexual_orientation']):
            pii_types.append('demographic')
        
        return pii_types or ['unknown']
    
    def mark_tainted(self, var_name: str, pii_types: List[str], source_line: int,
                    source_node: str = "unknown", taint_source: Optional[str] = None,
                    context: Optional[str] = None, is_sanitized: bool = False):
        """Mark a variable as tainted with PII"""
        print(f"DEBUG: mark_tainted called for {repr(var_name)}")
        if var_name not in self.tainted_vars:
            self.tainted_vars[var_name] = TaintInfo(
                variable_name=var_name,
                pii_types=pii_types,
                source_line=source_line,
                source_node=source_node,
                taint_source=taint_source,
                context=context,
                is_sanitized=is_sanitized,
                sources=[taint_source] if taint_source else []
            )
        else:
            # Update with new PII types
            existing = self.tainted_vars[var_name]
            existing.pii_types = list(set(existing.pii_types + pii_types))
            if existing.context is None and context:
                existing.context = context
            # If re-tainted with unsanitized data, it becomes unsanitized
            if not is_sanitized:
                existing.is_sanitized = False
            elif is_sanitized:
                existing.is_sanitized = True
        
        # print(f"DEBUG: Tainted vars: {list(self.tainted_vars.keys())}")
    
    def propagate_through_assignment(self, target: str, source: ast.expr, line: int, context: Optional[str] = None):
        """Propagate taint through assignment: target = source"""
        
        # Case 1: Direct assignment (x = y)
        if isinstance(source, ast.Name):
            if source.id in self.tainted_vars:
                source_taint = self.tainted_vars[source.id]
                self.mark_tainted(
                    target,
                    source_taint.pii_types,
                    line,
                    "assignment",
                    taint_source=source.id,
                    context=context,
                    is_sanitized=source_taint.is_sanitized
                )
                self.data_flow_edges.append(DataFlowEdge(
                    source_var=source.id,
                    target_var=target,
                    source_line=source_taint.source_line,
                    target_line=line,
                    flow_type="assignment",
                    context=context
                ))
        
        # Case 2: Attribute access (x = obj.email)
        elif isinstance(source, ast.Attribute):
            if self.is_tainted_attribute(source):
                attr_name = source.attr
                pii_types = self.infer_pii_type(attr_name)
                
                base_var = None
                if isinstance(source.value, ast.Name):
                    base_var = source.value.id
                
                self.mark_tainted(
                    target,
                    pii_types,
                    line,
                    "attribute_access",
                    taint_source=f"{base_var}.{attr_name}" if base_var else attr_name,
                    context=context
                )
                
                if base_var and base_var in self.tainted_vars:
                    self.data_flow_edges.append(DataFlowEdge(
                        source_var=base_var,
                        target_var=target,
                        source_line=self.tainted_vars[base_var].source_line,
                        target_line=line,
                        flow_type="attribute",
                        transformation=f"extract .{attr_name}",
                        context=context
                    ))
        
        # Case 3: Subscript (x = dict['email'])
        elif isinstance(source, ast.Subscript):
            if self.is_tainted(source.value):
                # Get key if it's a string
                key = None
                if isinstance(source.slice, ast.Constant):
                    key = source.slice.value
                
                if key:
                    pii_types = self.infer_pii_type(str(key))
                else:
                    # Inherit taint from container
                    base_taint = self.get_taint_info(source.value)
                    pii_types = base_taint.pii_types if base_taint else ['unknown']
                
                self.mark_tainted(target, pii_types, line, "subscript", context=context)
                
                # Add edge
                if isinstance(source.value, ast.Name) and source.value.id in self.tainted_vars:
                     self.data_flow_edges.append(DataFlowEdge(
                        source_var=source.value.id,
                        target_var=target,
                        source_line=self.tainted_vars[source.value.id].source_line,
                        target_line=line,
                        flow_type="subscript",
                        context=context
                    ))
        
        # Case 4: Function call (x = get_user())
        elif isinstance(source, ast.Call):
            # Check if any arguments are tainted
            tainted_args = [arg for arg in source.args if self.is_tainted(arg)]
            
            if tainted_args:
                # Aggregate PII types from all tainted arguments
                all_pii_types = []
                for arg in tainted_args:
                    taint = self.get_taint_info(arg)
                    if taint:
                        all_pii_types.extend(taint.pii_types)
                
                self.mark_tainted(
                    target,
                    list(set(all_pii_types)),
                    line,
                    "function_call",
                    taint_source="function_result",
                    context=context
                )
                
                # Add edges for each tainted arg
                for arg in tainted_args:
                    if isinstance(arg, ast.Name):
                         self.data_flow_edges.append(DataFlowEdge(
                            source_var=arg.id,
                            target_var=target,
                            source_line=self.tainted_vars[arg.id].source_line,
                            target_line=line,
                            flow_type="call",
                            transformation="function_call",
                            context=context
                        ))
    
    def track_function_call(self, call_node: ast.Call, line: int) -> List[str]:
        """Track tainted arguments in function calls and return tainted param names"""
        tainted_params = []
        
        for i, arg in enumerate(call_node.args):
            if self.is_tainted(arg):
                if isinstance(arg, ast.Name):
                    tainted_params.append(arg.id)
        
        return tainted_params

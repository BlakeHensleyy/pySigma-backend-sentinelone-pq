from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaString
from sigma.pipelines.sentinelone_pq import sentinelonepq_pipeline
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Union

class SentinelOnePQBackend(TextQueryBackend):
    """SentinelOne PowerQuery backend."""

    backend_processing_pipeline: ClassVar[ProcessingPipeline] = sentinelonepq_pipeline()

    name: ClassVar[str] = "SentinelOne PowerQuery backend"
    formats: Dict[str, str] = {
        "default": "Plaintext",
        "json": "JSON format"
    }

    requires_pipeline: bool = False

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    parenthesize: bool = True
    group_expression: ClassVar[str] = "({expr})"

    token_separator: str = " "
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = "="

    field_quote: ClassVar[str] = "'"
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^\w\.+$")
    field_quote_pattern_negation: ClassVar[bool] = False

    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = True
    field_escape_pattern: ClassVar[Pattern] = re.compile(r"\s")

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "*"
    add_escaped: ClassVar[str] = ""
    filter_chars: ClassVar[str] = ""
    bool_values: ClassVar[Dict[bool, str]] = {
        True: "true",
        False: "false",
    }

    startswith_expression: ClassVar[str] = "{field} contains {value}"
    endswith_expression: ClassVar[str] = "{field} contains {value}"
    contains_expression: ClassVar[str] = "{field} contains {value}"

    re_expression: ClassVar[str] = "{field} matches \"{regex}\""
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ()
    re_escape_escape_char: bool = True
    re_flag_prefix: bool = False

    case_sensitive_match_expression: ClassVar[str] = "{field} == {value}"
    case_sensitive_startswith_expression: ClassVar[str] = "{field} contains:matchcase {value}"
    case_sensitive_endswith_expression: ClassVar[str] = "{field} contains:matchcase {value}"
    case_sensitive_contains_expression: ClassVar[str] = "{field} contains:matchcase {value}"

    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = 'not ({field} matches "\\.*")'

    field_exists_expression: ClassVar[str] = '{field} matches "\\.*"'
    field_not_exists_expression: ClassVar[str] = 'not ({field} matches "\\.*")'

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "in"
    list_separator: ClassVar[str] = ","

    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    unbound_value_num_expression: ClassVar[str] = '"{value}"'

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        if isinstance(rule.detection.condition, str):
            condition_str = self.convert(rule.detection.condition, state)
        else:
            condition_str = self.build_condition(rule.detection.condition)

        query += condition_str

        if rule.fields:
            query += ' | columns ' + ",".join(rule.fields)
        
        return query

    def finalize_output_default(self, queries: List[str]) -> str:
        return queries

    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> dict:
        return {"query": query, "title": rule.title, "id": rule.id, "description": rule.description}

    def finalize_output_json(self, queries: List[str]) -> dict:
        return {"queries": queries}

    def build_condition(self, cond: Union[ConditionItem, List[ConditionItem]]) -> str:
        if isinstance(cond, list):
            if len(cond) == 1:
                return self.build_condition(cond[0])
            else:
                return f"({self.token_separator.join(self.build_condition(subcond) for subcond in cond)})"
        elif isinstance(cond, ConditionNOT):
            return f"{self.not_token} ({self.build_condition(cond.subcondition)})"
        elif isinstance(cond, ConditionAND):
            return f" {self.and_token} ".join(self.build_condition(subcond) for subcond in cond.subconditions)
        elif isinstance(cond, ConditionOR):
            return f" {self.or_token} ".join(self.build_condition(subcond) for subcond in cond.subconditions)
        elif isinstance(cond, ConditionFieldEqualsValueExpression):
            return self.compare_op_expression.format(field=cond.field, operator=self.eq_token, value=self.escape_value(cond.value))
        else:
            raise NotImplementedError(f"Unknown condition type {type(cond)}")

    def escape_value(self, value: Any) -> str:
        if isinstance(value, SigmaString):
            return f"{self.str_quote}{self.escape_char.join(value)}{self.str_quote}"
        elif isinstance(value, SigmaRegularExpression):
            return f"{self.re_expression.format(field=value.field, regex=self.escape_char.join(value.regex))}"
        else:
            return str(value)

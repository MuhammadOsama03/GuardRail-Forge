from guardrail_forge.models import Severity
from guardrail_forge.rules import PatternRule, RuleEngine


PROMPT_INJECTION_RULES = (
    PatternRule.compile(
        "prompt.invisible_obfuscation",
        "prompt_obfuscation",
        Severity.HIGH,
        "Invisible Unicode characters may conceal instructions",
        "[\\u200b\\u200c\\u200d\\u2060\\ufeff]",
    ),
    PatternRule.compile(
        "prompt.ignore_instructions",
        "prompt_injection",
        Severity.CRITICAL,
        "Attempt to override prior instructions",
        r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+instructions?\b",
    ),
    PatternRule.compile(
        "prompt.system_prompt",
        "prompt_injection",
        Severity.HIGH,
        "Attempt to reveal hidden instructions",
        r"\b(reveal|print|show|repeat)\s+(the\s+)?(system|developer)\s+prompt\b",
    ),
    PatternRule.compile(
        "prompt.role_override",
        "prompt_injection",
        Severity.HIGH,
        "Attempt to replace the assistant role",
        r"\b(you are now|act as|pretend to be)\b.{0,40}\b(unrestricted|jailbroken|developer mode)\b",
    ),
    PatternRule.compile(
        "prompt.encoded_payload",
        "prompt_injection",
        Severity.HIGH,
        "Instruction requests decoding and following an encoded payload",
        r"\b(decode|decrypt)\b.{0,40}\b(base64|encoded)\b.{0,40}\b(execute|follow|obey|run)\b",
    ),
    PatternRule.compile(
        "prompt.role_delimiter",
        "prompt_injection",
        Severity.HIGH,
        "Untrusted content contains a privileged role delimiter",
        r"(?:<\|\s*(?:system|developer)\s*\|>|\[\s*(?:system|developer)\s*\])",
    ),
)


def default_engine() -> RuleEngine:
    return RuleEngine(PROMPT_INJECTION_RULES)


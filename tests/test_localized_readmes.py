# ruff: noqa: RUF001

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README_FILES = (
    "README.md",
    "README.zh-CN.md",
    "README.zh-TW.md",
    "README.ja.md",
    "README.es.md",
    "README.fr.md",
    "README.de.md",
)
LANGUAGE_LABELS = (
    "English",
    "简体中文",
    "繁體中文",
    "日本語",
    "Español",
    "Français",
    "Deutsch",
)
LOCALIZED_TERMINOLOGY = (
    (
        "README.zh-CN.md",
        (
            "子任务（Child Mission，即独立的 Mission，而非工作项）",
            "工作项授权、发出 Work Offer、接受 Work Offer",
            "通过正式 Work Proposal 提出的下级工作项",
            "工作项阻塞与恢复",
        ),
        (
            "子 Mission",
            "子安全 Mission",
            "正式提出的子任务",
            "任务阻塞与恢复",
            "发出任务",
            "接受任务",
            "Mission/WorkItem",
            "而非 WorkItem",
            "后代工作项",
        ),
    ),
    (
        "README.zh-TW.md",
        (
            "子任務（Child Mission，即獨立的 Mission，而非工作項）",
            "工作項授權、發出 Work Offer、接受 Work Offer",
            "透過正式 Work Proposal 提出的下層工作項",
            "工作項受阻與復原",
        ),
        (
            "子 Mission",
            "子安全 Mission",
            "正式提出的子任務",
            "任務受阻與復原",
            "發出任務",
            "接受任務",
            "Mission/WorkItem",
            "而非 WorkItem",
            "後代工作項",
        ),
    ),
    (
        "README.ja.md",
        (
            "サブタスク（Child Mission。独立した Mission であり、WorkItem ではない）",
            "Work Proposal を通じて提案する下位の WorkItem",
            "セキュリティのサブタスク",
            "WorkItem のブロック／再開",
        ),
        (
            "子 Mission",
            "子 security Mission",
            "子ミッション",
            "sub-work",
            "work の block/resume",
        ),
    ),
    (
        "README.es.md",
        (
            "subtareas recursivas (Child Mission), cada una de ellas una Mission "
            "independiente y no un WorkItem",
            "WorkItem subordinado propuesto formalmente",
            "mediante una Work Proposal",
            "una subtarea de seguridad",
            "WorkItem bloqueado",
        ),
        (
            "Mission hija",
            "Mission secundarias",
            "WorkItem descendiente",
            "sub-work",
            "trabajo bloqueado",
        ),
    ),
    (
        "README.fr.md",
        (
            "sous-tâches récursives (Child Mission), chacune étant une Mission "
            "indépendante et non un WorkItem",
            "WorkItem subordonné proposé formellement",
            "au moyen d’une Work Proposal",
            "une sous-tâche de sécurité",
            "WorkItem bloqué",
        ),
        (
            "Mission enfant",
            "des Child Mission",
            "une Child Mission",
            "WorkItem descendant",
            "sous-travail",
            "du travail bloqué",
        ),
    ),
    (
        "README.de.md",
        (
            "rekursive Unteraufgaben (Child Mission), jeweils eine eigenständige Mission "
            "und kein WorkItem",
            "per Work Proposal vorgeschlagenes untergeordnetes WorkItem",
            "zwei gleichzeitige Softwareentwicklungs-Missionen",
            "eine Unteraufgabe für die Sicherheitsprüfung",
            "Klärungen zwischen Workern",
            "zwei isolierte Capacity Slots",
            "blockiertes und wiederaufgenommenes WorkItem",
            "exakt signierte finale Approvals",
        ),
        (
            "rekursive Child Mission",
            "einer Child Mission",
            "untergeordnete Mission",
            "eine Unteraufgabe für Sicherheit",
            "Unterarbeit",
            "fortgesetzter Arbeit",
            "blockierten und fortgesetzten WorkItem",
            "Das deterministische Szenario führt",
        ),
    ),
)


@pytest.mark.parametrize("readme", README_FILES)
def test_readme_language_switcher_lists_all_seven_languages(readme: str) -> None:
    switcher = "\n".join((ROOT / readme).read_text(encoding="utf-8").splitlines()[:3])

    for label in LANGUAGE_LABELS:
        assert label in switcher, f"{readme} is missing the {label} language switcher"


@pytest.mark.parametrize(("readme", "required", "retired"), LOCALIZED_TERMINOLOGY)
def test_localized_readme_keeps_mission_and_workitem_distinct(
    readme: str,
    required: tuple[str, ...],
    retired: tuple[str, ...],
) -> None:
    content = " ".join((ROOT / readme).read_text(encoding="utf-8").split())

    for phrase in required:
        assert phrase in content, f"{readme} is missing canonical terminology: {phrase}"
    for phrase in retired:
        assert phrase not in content, (
            f"{readme} contains retired or ambiguous terminology: {phrase}"
        )

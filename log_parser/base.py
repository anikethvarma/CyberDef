"""
Base Parser

Abstract base class and registry for CSV parsers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Type
from uuid import UUID

from shared_models.events import ParsedEvent, RawEventRow
from core.logging import get_logger

logger = get_logger(__name__)


class BaseParser(ABC):
    """
    Abstract base class for CSV parsers.
    
    Each parser handles a specific device/vendor log format.
    """
    
    # Parser identification
    name: str = "base"
    vendor: str = "unknown"
    description: str = "Base parser"
    
    # Column mappings (override in subclasses)
    column_mappings: dict[str, list[str]] = {}
    
    def __init__(self):
        self.parse_errors: list[str] = []
        self.rows_parsed: int = 0
        self.rows_failed: int = 0
    
    @abstractmethod
    def can_parse(self, columns: list[str], sample_rows: list[dict[str, Any]]) -> float:
        """
        Determine if this parser can handle the given file.
        
        Args:
            columns: Column names from the CSV
            sample_rows: First few rows of data
            
        Returns:
            Confidence score between 0 and 1
        """
        pass
    
    @abstractmethod
    def parse_row(self, raw_row: RawEventRow) -> ParsedEvent:
        """
        Parse a single row into a ParsedEvent.
        
        Args:
            raw_row: Raw row data from CSV
            
        Returns:
            ParsedEvent with extracted fields
        """
        pass
    
    def parse_batch(self, raw_rows: list[RawEventRow]) -> list[ParsedEvent]:
        """
        Parse a batch of rows.
        
        Args:
            raw_rows: List of raw rows
            
        Returns:
            List of parsed events
        """
        events = []
        
        for raw_row in raw_rows:
            try:
                event = self.parse_row(raw_row)
                events.append(event)
                self.rows_parsed += 1
            except Exception as e:
                self.rows_failed += 1
                self.parse_errors.append(
                    f"Row {raw_row.row_number}: {str(e)}"
                )
                logger.warning(
                    f"Failed to parse row | row_number={raw_row.row_number}, error={e}"
                )
        
        return events
    
    def find_column(self, data: dict[str, Any], field_name: str) -> Any | None:
        """
        Find a column value using multiple possible column names.
        
        Args:
            data: Row data dictionary
            field_name: Logical field name to look up
            
        Returns:
            Column value if found, None otherwise
        """
        possible_names = self.column_mappings.get(field_name, [field_name])
        
        for name in possible_names:
            # Try exact match
            if name in data:
                return data[name]
            
            # Try case-insensitive match
            for key in data.keys():
                if key.lower() == name.lower():
                    return data[key]
        
        return None
    
    def _clean_value(self, value: Any, placeholders: list[str] = None) -> str | None:
        """
        Clean a value by treating common placeholders as None.
        
        Args:
            value: The value to clean
            placeholders: List of placeholder strings to treat as None (default: ["-", ""])
            
        Returns:
            Cleaned string value or None if it's a placeholder
        """
        if value is None:
            return None
        
        if placeholders is None:
            placeholders = ["-", ""]
        
        s = str(value).strip()
        if s in placeholders:
            return None
        
        return s
    
    def _clean_ip(self, value: Any) -> str | None:
        """
        Clean an IP address value, treating "-" and other placeholders as None.
        
        Args:
            value: The IP address value to clean
            
        Returns:
            Cleaned IP string or None if it's a placeholder
        """
        return self._clean_value(value, placeholders=["-", "", "0.0.0.0"])
    
    def get_stats(self) -> dict[str, Any]:
        """Get parsing statistics."""
        return {
            "parser": self.name,
            "vendor": self.vendor,
            "rows_parsed": self.rows_parsed,
            "rows_failed": self.rows_failed,
            "error_count": len(self.parse_errors),
            "success_rate": (
                self.rows_parsed / (self.rows_parsed + self.rows_failed)
                if (self.rows_parsed + self.rows_failed) > 0
                else 0
            ),
        }


class ParserRegistry:
    """
    Registry for available parsers.
    
    Manages parser discovery and selection based on file content.
    """
    
    _parsers: dict[str, Type[BaseParser]] = {}
    
    @classmethod
    def register(cls, parser_class: Type[BaseParser]) -> Type[BaseParser]:
        """
        Register a parser class.
        
        Can be used as a decorator:
        @ParserRegistry.register
        class MyParser(BaseParser):
            ...
        """
        cls._parsers[parser_class.name] = parser_class
        logger.debug(f"Registered parser: {parser_class.name}")
        return parser_class
    
    @classmethod
    def get_parser(cls, name: str) -> BaseParser | None:
        """Get a parser by name."""
        parser_class = cls._parsers.get(name)
        if parser_class:
            return parser_class()
        return None
    
    @classmethod
    def detect_parser(
        cls,
        columns: list[str],
        sample_rows: list[dict[str, Any]],
    ) -> BaseParser:
        """
        Detect the best parser for the given file.
        
        Args:
            columns: Column names
            sample_rows: Sample data rows
            
        Returns:
            Best matching parser instance
        """
        best_parser = None
        best_confidence = 0.0
        
        for name, parser_class in cls._parsers.items():
            parser = parser_class()
            confidence = parser.can_parse(columns, sample_rows)
            
            logger.debug(
                f"Parser confidence | parser={name}, confidence={confidence}"
            )
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_parser = parser
        
        if best_parser is None:
            # Return generic parser as fallback
            from log_parser.generic_parser import GenericCSVParser
            best_parser = GenericCSVParser()
        
        logger.info(
            f"Selected parser | parser={best_parser.name}, confidence={best_confidence}"
        )
        
        return best_parser
    
    @classmethod
    def list_parsers(cls) -> list[dict[str, str]]:
        """List all registered parsers."""
        return [
            {
                "name": p.name,
                "vendor": p.vendor,
                "description": p.description,
            }
            for p in cls._parsers.values()
        ]

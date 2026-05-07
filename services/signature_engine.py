import logging
import sqlite3
import csv
from io import StringIO
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import hashlib

logger = logging.getLogger(__name__)


class SignatureEngine:
    """
    SQLite-based signature database engine.
    Uses a separate SQLite database (not SQLAlchemy).
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the signature engine with a SQLite database.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema if it doesn't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    sha256 TEXT PRIMARY KEY,
                    name TEXT,
                    severity TEXT,
                    category TEXT,
                    source TEXT,
                    added_at TEXT
                )
            """)
            
            # Create index for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_signatures_name 
                ON signatures(name)
            """)
            
            conn.commit()
            logger.info(f"Signature database initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize signature database: {e}")
            raise
        finally:
            conn.close()
    
    def check_file(self, file_bytes: bytes) -> Dict:
        """
        Check if a file (by its SHA-256 hash) is in the signature database.
        
        Args:
            file_bytes: The file content as bytes
        
        Returns:
            dict: {found, sha256, name, severity, category, source}
        """
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        return self.check_hash(sha256)
    
    def check_hash(self, sha256: str) -> Dict:
        """
        Check if a SHA-256 hash is in the signature database.
        
        Args:
            sha256: The SHA-256 hash (hex string)
        
        Returns:
            dict: {found, sha256, name, severity, category, source}
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT name, severity, category, source FROM signatures WHERE sha256 = ?",
                (sha256,)
            )
            result = cursor.fetchone()
            
            if result:
                return {
                    "found": True,
                    "sha256": sha256,
                    "name": result[0],
                    "severity": result[1],
                    "category": result[2],
                    "source": result[3]
                }
            else:
                return {
                    "found": False,
                    "sha256": sha256,
                    "name": None,
                    "severity": None,
                    "category": None,
                    "source": None
                }
        except Exception as e:
            logger.error(f"Error checking hash in database: {e}")
            return {
                "found": False,
                "sha256": sha256,
                "name": None,
                "severity": None,
                "category": None,
                "source": None
            }
        finally:
            conn.close()
    
    def add_signature(self, sha256: str, name: str, severity: str, 
                     category: str, source: str) -> bool:
        """
        Add a single signature to the database.
        
        Args:
            sha256: SHA-256 hash
            name: Malware/file name
            severity: Severity level
            category: File category/type
            source: Source (e.g., "MalwareBazaar")
        
        Returns:
            bool: True if inserted, False if already exists or error
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR IGNORE INTO signatures 
                (sha256, name, severity, category, source, added_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sha256, name, severity, category, source, datetime.utcnow().isoformat()))
            
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error adding signature: {e}")
            return False
        finally:
            conn.close()
    
    def bulk_import_csv(self, csv_content: str) -> Dict:
        """
        Bulk import signatures from CSV content.
        Expected columns: sha256_hash, file_name, file_type_mime, reporter, tags
        (MalwareBazaar format)
        
        Args:
            csv_content: CSV content as string
        
        Returns:
            dict: {imported, skipped, errors}
        """
        imported = 0
        skipped = 0
        errors = []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Parse CSV
            reader = csv.DictReader(StringIO(csv_content))
            
            for row_num, row in enumerate(reader, start=2):  # Start at 2 (skip header)
                try:
                    sha256 = row.get("sha256_hash", "").strip().lower()
                    name = row.get("file_name", "").strip()
                    category = row.get("file_type_mime", "").strip()
                    source = "MalwareBazaar"
                    severity = "HIGH"  # Default severity
                    
                    # Validate SHA-256 format
                    if not sha256 or len(sha256) != 64:
                        skipped += 1
                        errors.append(f"Row {row_num}: Invalid SHA-256 hash")
                        continue
                    
                    # Try to insert
                    cursor.execute("""
                        INSERT OR IGNORE INTO signatures 
                        (sha256, name, severity, category, source, added_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (sha256, name, severity, category, source, datetime.utcnow().isoformat()))
                    
                    if cursor.rowcount > 0:
                        imported += 1
                    else:
                        skipped += 1
                
                except KeyError as e:
                    skipped += 1
                    errors.append(f"Row {row_num}: Missing column {e}")
                except Exception as e:
                    skipped += 1
                    errors.append(f"Row {row_num}: {str(e)}")
            
            conn.commit()
            logger.info(f"Bulk import completed: {imported} imported, {skipped} skipped")
            
        except Exception as e:
            logger.error(f"Error during bulk import: {e}")
            errors.append(f"Import failed: {str(e)}")
        finally:
            conn.close()
        
        return {
            "imported": imported,
            "skipped": skipped,
            "errors": errors
        }
    
    def get_stats(self) -> Dict:
        """
        Get statistics about the signature database.
        
        Returns:
            dict: {total, by_severity, by_category}
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total signatures
            cursor.execute("SELECT COUNT(*) FROM signatures")
            total = cursor.fetchone()[0]
            
            # By severity
            cursor.execute("""
                SELECT severity, COUNT(*) FROM signatures 
                GROUP BY severity
            """)
            by_severity = {row[0]: row[1] for row in cursor.fetchall()}
            
            # By category
            cursor.execute("""
                SELECT category, COUNT(*) FROM signatures 
                GROUP BY category
            """)
            by_category = {row[0]: row[1] for row in cursor.fetchall()}
            
            return {
                "total": total,
                "by_severity": by_severity,
                "by_category": by_category
            }
        except Exception as e:
            logger.error(f"Error getting signature stats: {e}")
            return {"total": 0, "by_severity": {}, "by_category": {}}
        finally:
            conn.close()
    
    def list_signatures(self, page: int = 1, limit: int = 20, 
                       search: Optional[str] = None) -> Dict:
        """
        List signatures with pagination and optional search.
        
        Args:
            page: Page number (1-indexed)
            limit: Items per page
            search: Search string (searches name and source)
        
        Returns:
            dict: {signatures, total}
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            offset = (page - 1) * limit
            
            if search:
                search_term = f"%{search}%"
                cursor.execute("""
                    SELECT sha256, name, severity, category, source, added_at 
                    FROM signatures 
                    WHERE name LIKE ? OR source LIKE ?
                    ORDER BY added_at DESC
                    LIMIT ? OFFSET ?
                """, (search_term, search_term, limit, offset))
                
                cursor.execute("""
                    SELECT COUNT(*) FROM signatures 
                    WHERE name LIKE ? OR source LIKE ?
                """, (search_term, search_term))
            else:
                cursor.execute("""
                    SELECT sha256, name, severity, category, source, added_at 
                    FROM signatures 
                    ORDER BY added_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
                
                cursor.execute("SELECT COUNT(*) FROM signatures")
            
            total = cursor.fetchone()[0]
            
            # Re-query for signatures (need to reset cursor)
            if search:
                search_term = f"%{search}%"
                cursor.execute("""
                    SELECT sha256, name, severity, category, source, added_at 
                    FROM signatures 
                    WHERE name LIKE ? OR source LIKE ?
                    ORDER BY added_at DESC
                    LIMIT ? OFFSET ?
                """, (search_term, search_term, limit, offset))
            else:
                cursor.execute("""
                    SELECT sha256, name, severity, category, source, added_at 
                    FROM signatures 
                    ORDER BY added_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
            
            signatures = [
                {
                    "sha256": row[0],
                    "name": row[1],
                    "severity": row[2],
                    "category": row[3],
                    "source": row[4],
                    "added_at": row[5]
                }
                for row in cursor.fetchall()
            ]
            
            return {"signatures": signatures, "total": total}
        except Exception as e:
            logger.error(f"Error listing signatures: {e}")
            return {"signatures": [], "total": 0}
        finally:
            conn.close()
    
    def delete_signature(self, sha256: str) -> bool:
        """
        Delete a signature from the database.
        
        Args:
            sha256: SHA-256 hash
        
        Returns:
            bool: True if deleted, False if not found or error
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM signatures WHERE sha256 = ?", (sha256,))
            conn.commit()
            
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error deleting signature: {e}")
            return False
        finally:
            conn.close()

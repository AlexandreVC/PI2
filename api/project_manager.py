"""
Project Manager for VulnAI Platform.

Manages projects and their associated files for targeted scanning.
Each project is a folder containing files to be analyzed.
"""

import os
import json
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class Project:
    """Represents a scanning project."""
    id: str
    name: str
    description: str = ""
    created_at: str = ""
    updated_at: str = ""
    file_count: int = 0
    total_size: int = 0
    last_scan: Optional[str] = None
    scan_count: int = 0
    vulnerability_count: int = 0


class ProjectManager:
    """
    Manages projects for organized vulnerability scanning.

    Each project has its own folder where files can be uploaded
    and selectively scanned.
    """

    def __init__(self, base_dir: str = "data/projects"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.base_dir / "projects.json"
        self.projects: Dict[str, Project] = {}
        self._load_metadata()

    def _load_metadata(self):
        """Load projects metadata from disk."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for proj_data in data.get('projects', []):
                        proj = Project(**proj_data)
                        self.projects[proj.id] = proj
                logger.info(f"Loaded {len(self.projects)} projects")
            except Exception as e:
                logger.error(f"Failed to load projects metadata: {e}")

    def _save_metadata(self):
        """Save projects metadata to disk."""
        try:
            data = {
                'projects': [asdict(p) for p in self.projects.values()],
                'updated_at': datetime.now().isoformat()
            }
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save projects metadata: {e}")

    def _generate_id(self, name: str) -> str:
        """Generate a unique project ID from name."""
        import re
        base_id = re.sub(r'[^a-zA-Z0-9]', '-', name.lower()).strip('-')
        base_id = re.sub(r'-+', '-', base_id)

        if base_id not in self.projects:
            return base_id

        counter = 1
        while f"{base_id}-{counter}" in self.projects:
            counter += 1
        return f"{base_id}-{counter}"

    def create_project(self, name: str, description: str = "") -> Project:
        """Create a new project."""
        project_id = self._generate_id(name)
        project_dir = self.base_dir / project_id
        project_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now().isoformat()
        project = Project(
            id=project_id,
            name=name,
            description=description,
            created_at=now,
            updated_at=now
        )

        self.projects[project_id] = project
        self._save_metadata()
        logger.info(f"Created project: {name} ({project_id})")

        return project

    def get_project(self, project_id: str) -> Optional[Project]:
        """Get a project by ID."""
        return self.projects.get(project_id)

    def list_projects(self) -> List[Project]:
        """List all projects."""
        # Update file counts before returning
        for project in self.projects.values():
            self._update_project_stats(project)
        self._save_metadata()
        return list(self.projects.values())

    def delete_project(self, project_id: str) -> bool:
        """Delete a project and all its files."""
        if project_id not in self.projects:
            return False

        project_dir = self.base_dir / project_id
        if project_dir.exists():
            shutil.rmtree(project_dir)

        del self.projects[project_id]
        self._save_metadata()
        logger.info(f"Deleted project: {project_id}")
        return True

    def update_project(self, project_id: str, name: str = None, description: str = None) -> Optional[Project]:
        """Update project metadata."""
        project = self.projects.get(project_id)
        if not project:
            return None

        if name:
            project.name = name
        if description is not None:
            project.description = description
        project.updated_at = datetime.now().isoformat()

        self._save_metadata()
        return project

    def _update_project_stats(self, project: Project):
        """Update project file statistics."""
        project_dir = self.base_dir / project.id
        if not project_dir.exists():
            project.file_count = 0
            project.total_size = 0
            return

        files = list(project_dir.rglob("*"))
        files = [f for f in files if f.is_file()]

        project.file_count = len(files)
        project.total_size = sum(f.stat().st_size for f in files)

    def get_project_dir(self, project_id: str) -> Optional[Path]:
        """Get the directory path for a project."""
        if project_id not in self.projects:
            return None
        return self.base_dir / project_id

    def add_file(self, project_id: str, filename: str, content: bytes) -> Dict[str, Any]:
        """Add a file to a project."""
        project = self.projects.get(project_id)
        if not project:
            raise ValueError(f"Project not found: {project_id}")

        project_dir = self.base_dir / project_id
        project_dir.mkdir(parents=True, exist_ok=True)

        # Handle subdirectories in filename
        file_path = project_dir / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, 'wb') as f:
            f.write(content)

        # Update project stats
        project.updated_at = datetime.now().isoformat()
        self._update_project_stats(project)
        self._save_metadata()

        return {
            "id": filename,
            "name": filename,
            "path": str(file_path.relative_to(self.base_dir)),
            "size": len(content),
            "project_id": project_id
        }

    def list_files(self, project_id: str) -> List[Dict[str, Any]]:
        """List all files in a project."""
        project = self.projects.get(project_id)
        if not project:
            return []

        project_dir = self.base_dir / project_id
        if not project_dir.exists():
            return []

        files = []
        for f in project_dir.rglob("*"):
            if f.is_file():
                rel_path = f.relative_to(project_dir)
                files.append({
                    "id": str(rel_path),
                    "name": f.name,
                    "path": str(rel_path),
                    "full_path": str(f),
                    "size": f.stat().st_size,
                    "extension": f.suffix.lower(),
                    "modified_at": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                })

        return sorted(files, key=lambda x: x["path"])

    def get_file_content(self, project_id: str, file_path: str) -> Optional[bytes]:
        """Get the content of a file."""
        project_dir = self.base_dir / project_id
        full_path = project_dir / file_path

        if not full_path.exists() or not full_path.is_file():
            return None

        with open(full_path, 'rb') as f:
            return f.read()

    def delete_file(self, project_id: str, file_path: str) -> bool:
        """Delete a file from a project."""
        project = self.projects.get(project_id)
        if not project:
            return False

        project_dir = self.base_dir / project_id
        full_path = project_dir / file_path

        if not full_path.exists():
            return False

        full_path.unlink()

        # Clean up empty directories
        parent = full_path.parent
        while parent != project_dir:
            if not any(parent.iterdir()):
                parent.rmdir()
            parent = parent.parent

        # Update stats
        project.updated_at = datetime.now().isoformat()
        self._update_project_stats(project)
        self._save_metadata()

        return True

    def record_scan(self, project_id: str, vulnerability_count: int):
        """Record that a scan was performed on this project."""
        project = self.projects.get(project_id)
        if project:
            project.last_scan = datetime.now().isoformat()
            project.scan_count += 1
            project.vulnerability_count = vulnerability_count
            self._save_metadata()

    def get_scannable_files(self, project_id: str, file_ids: List[str] = None) -> List[Path]:
        """
        Get files to scan from a project.

        Args:
            project_id: The project ID
            file_ids: Optional list of specific file paths to scan.
                     If None, returns all scannable files.

        Returns:
            List of Path objects for files to scan
        """
        project_dir = self.base_dir / project_id
        if not project_dir.exists():
            return []

        # Scannable extensions
        scannable_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.h',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.sql', '.html', '.xml', '.json', '.yaml', '.yml', '.sh', '.bash',
            '.ps1', '.config', '.env', '.ini', '.conf'
        }

        files_to_scan = []

        if file_ids:
            # Scan specific files
            for file_id in file_ids:
                file_path = project_dir / file_id
                if file_path.exists() and file_path.is_file():
                    if file_path.suffix.lower() in scannable_extensions:
                        files_to_scan.append(file_path)
        else:
            # Scan all scannable files
            for f in project_dir.rglob("*"):
                if f.is_file() and f.suffix.lower() in scannable_extensions:
                    files_to_scan.append(f)

        return files_to_scan


# Global instance
_project_manager: Optional[ProjectManager] = None


def get_project_manager() -> ProjectManager:
    """Get or create the global ProjectManager instance."""
    global _project_manager
    if _project_manager is None:
        _project_manager = ProjectManager()
    return _project_manager

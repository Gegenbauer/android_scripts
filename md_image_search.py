#!/usr/bin/env python3
"""
Script to search for images used in Markdown files and copy them to organized directories.
"""
import re
import shutil
from pathlib import Path
from script_base.script_manager import ScriptManager, Command
from script_base.utils import ensure_directory_exists
from script_base.log import logger

class SearchImagesCommand(Command):
    """
    Search for all images used in Markdown files within a specified folder.
    Returns absolute paths of images referenced in the Markdown files.
    """
    def add_arguments(self, parser):
        parser.add_argument("--folder", type=str, required=True, help="Folder to scan for Markdown files.")
        parser.add_argument("--image-folder", type=str, help="Base folder for resolving relative image paths (optional, defaults to the Markdown file's directory).")

    def execute(self, args):
        folder = Path(args.folder).resolve()
        if not folder.exists() or not folder.is_dir():
            logger.error(f"Folder does not exist or is not a directory: {folder}")
            return
        image_folder = Path(args.image_folder).resolve() if args.image_folder else None
        used_images = set()
        md_files = list(folder.rglob("*.md"))
        if not md_files:
            logger.info(f"No Markdown files found in {folder}")
            return
        for md_file in md_files:
            try:
                with open(md_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                # Regex to find image references: ![alt](path)
                image_refs = re.findall(r'!\[.*?\]\((.*?)\)', content)
                for ref in image_refs:
                    # Remove query params or fragments if any
                    ref = ref.split('?')[0].split('#')[0]
                    if ref.startswith('http://') or ref.startswith('https://'):
                        continue  # Skip external URLs
                    # Resolve path
                    if Path(ref).is_absolute():
                        img_path = Path(ref)
                    else:
                        base_dir = image_folder if image_folder else md_file.parent
                        img_path = (base_dir / ref).resolve()
                    if img_path.exists() and img_path.is_file():
                        used_images.add(str(img_path))
                    else:
                        logger.warning(f"Referenced image not found: {img_path} in {md_file}")
            except Exception as e:
                logger.error(f"Error scanning {md_file}: {e}", exc_info=True)
        # Output the list
        if used_images:
            logger.info("Used images:")
            for img in sorted(used_images):
                print(img)
        else:
            logger.info("No images found.")

class CopyImagesCommand(Command):
    """
    Copy images from a specified image folder to an output directory, organizing into 'used' and 'unused' subfolders based on images referenced in Markdown files within a specified folder.
    """
    def add_arguments(self, parser):
        parser.add_argument("--folder", type=str, required=True, help="Folder to scan for Markdown files to determine used images.")
        parser.add_argument("--image-folder", type=str, required=True, help="Folder containing images to copy.")
        parser.add_argument("--output-dir", type=str, required=True, help="Output directory to copy images to.")
        parser.add_argument("--image-base-folder", type=str, help="Base folder for resolving relative image paths in Markdown (optional, defaults to the Markdown file's directory).")

    def execute(self, args):
        folder = Path(args.folder).resolve()
        if not folder.exists() or not folder.is_dir():
            logger.error(f"Folder does not exist or is not a directory: {folder}")
            return
        image_folder = Path(args.image_folder).resolve()
        if not image_folder.exists() or not image_folder.is_dir():
            logger.error(f"Image folder does not exist or is not a directory: {image_folder}")
            return
        output_dir = Path(args.output_dir).resolve()
        ensure_directory_exists(output_dir)
        used_dir = output_dir / "used"
        unused_dir = output_dir / "unused"
        ensure_directory_exists(used_dir)
        ensure_directory_exists(unused_dir)
        image_base_folder = Path(args.image_base_folder).resolve() if args.image_base_folder else None
        # Get used image filenames from Markdown
        used_filenames = set()
        md_files = list(folder.rglob("*.md"))
        for md_file in md_files:
            try:
                with open(md_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                image_refs = re.findall(r'!\[.*?\]\((.*?)\)', content)
                for ref in image_refs:
                    ref = ref.split('?')[0].split('#')[0]
                    if ref.startswith('http://') or ref.startswith('https://'):
                        continue
                    if Path(ref).is_absolute():
                        img_path = Path(ref)
                    else:
                        base_dir = image_base_folder if image_base_folder else md_file.parent
                        img_path = (base_dir / ref).resolve()
                    if img_path.exists() and img_path.is_file():
                        used_filenames.add(img_path.name)
            except Exception as e:
                logger.error(f"Error scanning {md_file}: {e}", exc_info=True)
        # Get all images in image_folder
        image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp'}
        all_images = [p for p in image_folder.rglob('*') if p.is_file() and p.suffix.lower() in image_extensions]
        for img_path in all_images:
            if img_path.name in used_filenames:
                dest = used_dir / img_path.name
                shutil.copy2(img_path, dest)
                logger.info(f"Copied used image: {img_path} -> {dest}")
            else:
                dest = unused_dir / img_path.name
                shutil.copy2(img_path, dest)
                logger.info(f"Copied unused image: {img_path} -> {dest}")

class UpdateImageRefsCommand(Command):
    """
    Update image references in Markdown files within a specified folder to point to a specified URL prefix, and output the modified files to a specified output directory.
    """
    def add_arguments(self, parser):
        parser.add_argument("--folder", type=str, required=True, help="Folder to scan for Markdown files.")
        parser.add_argument("--prefix", type=str, required=True, help="URL prefix to prepend to image filenames, e.g., https://example.com/pics/")
        parser.add_argument("--output-dir", type=str, required=True, help="Output directory to save modified Markdown files.")

    def execute(self, args):
        folder = Path(args.folder).resolve()
        if not folder.exists() or not folder.is_dir():
            logger.error(f"Folder does not exist or is not a directory: {folder}")
            return
        prefix = args.prefix.rstrip('/')
        output_dir = Path(args.output_dir).resolve()
        ensure_directory_exists(output_dir)
        md_files = list(folder.rglob("*.md"))
        if not md_files:
            logger.info(f"No Markdown files found in {folder}")
            return
        for md_file in md_files:
            try:
                with open(md_file, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                # Regex to find image references: ![alt](path)
                def replace_ref(match):
                    alt = match.group(1)
                    path = match.group(2)
                    # Extract filename
                    filename = Path(path.split('?')[0].split('#')[0]).name
                    new_path = f"{prefix}/{filename}"
                    return f"![{alt}]({new_path})"
                new_content = re.sub(r'!\[(.*?)\]\((.*?)\)', replace_ref, content)
                # Determine output path
                relative_path = md_file.relative_to(folder)
                output_file = output_dir / relative_path
                ensure_directory_exists(output_file.parent)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                logger.info(f"Updated and saved: {md_file} -> {output_file}")
            except Exception as e:
                logger.error(f"Error processing {md_file}: {e}", exc_info=True)

if __name__ == "__main__":
    manager = ScriptManager(description="Markdown image search and copy utility.\n\nUsage examples:\n  python md_image_search.py search-images --folder ./docs\n  python md_image_search.py copy-images --folder ./docs --image-folder ./images --output-dir ./output\n  python md_image_search.py update-image-refs --folder ./docs --prefix https://example.com/pics/ --output-dir ./output\n")
    manager.register_command("search-images", SearchImagesCommand(), help_text="Search for images used in Markdown files.")
    manager.register_command("copy-images", CopyImagesCommand(), help_text="Copy images to organized directories based on usage.")
    manager.register_command(
        "update-image-refs",
        UpdateImageRefsCommand(),
        help_text="Update image references in Markdown files to a specified URL prefix."
    )
    manager.run()
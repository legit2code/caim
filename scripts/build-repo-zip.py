import os
import zipfile

def create_repo_zip():
    exclude_dirs = {'.git', 'node_modules', 'dist', '.vite', '.turbo', '.cache'}
    zip_filename = 'caim-repository.zip'
    public_dest = os.path.join('public', 'caim-repository.zip')

    def should_include(relpath):
        parts = relpath.split(os.sep)
        for part in parts:
            if part in exclude_dirs:
                return False
        if relpath.endswith('.zip'):
            return False
        return True

    print(f"Creating {zip_filename}...")
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk('.'):
            # filter dirs in place
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                filepath = os.path.join(root, file)
                relpath = os.path.relpath(filepath, '.')
                if should_include(relpath):
                    zipf.write(filepath, relpath)

    size_mb = os.path.getsize(zip_filename) / (1024 * 1024)
    print(f"Successfully generated {zip_filename} ({size_mb:.2f} MB)")

    # Copy to public/ for direct browser download if needed
    os.makedirs('public', exist_ok=True)
    import shutil
    shutil.copyfile(zip_filename, public_dest)
    print(f"Copied archive to {public_dest}")

if __name__ == '__main__':
    create_repo_zip()

"""
Setup script for Maritime IDS project
Run this after installing requirements to set up the project structure
"""
import os
import sys
from pathlib import Path

def create_directories():
    """Create necessary directories"""
    base_dir = Path(__file__).parent
    
    directories = [
        'data/raw',
        'data/processed',
        'trained_models',
        'logs',
        'templates',
        'static/css',
        'static/js',
        'static/images'
    ]
    
    print("Creating directory structure...")
    for directory in directories:
        dir_path = base_dir / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created: {directory}")


def create_env_file():
    """Create .env file from example if it doesn't exist"""
    base_dir = Path(__file__).parent
    env_file = base_dir / '.env'
    env_example = base_dir / '.env.example'
    
    if not env_file.exists() and env_example.exists():
        print("\nCreating .env file from template...")
        with open(env_example, 'r') as src, open(env_file, 'w') as dst:
            dst.write(src.read())
        print("✓ Created .env file (please update with your credentials)")
    elif env_file.exists():
        print("\n✓ .env file already exists")
    else:
        print("\n⚠ Warning: .env.example not found")


def create_readme_notice():
    """Create a notice about data download"""
    base_dir = Path(__file__).parent
    data_readme = base_dir / 'data' / 'raw' / 'README.md'
    
    content = """# Data Directory

## NSL-KDD Dataset Required

Please download the NSL-KDD dataset and place the following files here:

1. **KDDTrain+.txt** - Training dataset
2. **KDDTest+.txt** - Testing dataset

### Download Links:
- Official: https://www.unb.ca/cic/datasets/nsl.html
- Alternative: https://github.com/jmnwong/NSL-KDD-Dataset

### Dataset Information:
- NSL-KDD is an improved version of the KDD'99 dataset
- Contains network intrusion detection data
- ~125,000 training samples
- ~22,500 test samples
- 41 features per sample

### Note:
The files should be named exactly as:
- `KDDTrain+.txt`
- `KDDTest+.txt`

After downloading, your directory structure should look like:
```
data/
└── raw/
    ├── KDDTrain+.txt
    ├── KDDTest+.txt
    └── README.md (this file)
```
"""
    
    print("\nCreating data directory instructions...")
    with open(data_readme, 'w') as f:
        f.write(content)
    print("✓ Created data/raw/README.md")


def check_python_version():
    """Check Python version"""
    print("\nChecking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro} - OK")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.8+")
        return False


def print_next_steps():
    """Print next steps for the user"""
    print("\n" + "="*60)
    print("Setup Complete!")
    print("="*60)
    print("\nNext Steps:")
    print("\n1. Install dependencies:")
    print("   pip install -r requirements.txt")
    print("\n2. Download NSL-KDD dataset:")
    print("   - See instructions in: data/raw/README.md")
    print("   - Place files in: data/raw/")
    print("\n3. Configure environment:")
    print("   - Edit .env file with your email credentials")
    print("\n4. Train models:")
    print("   python train.py")
    print("\n5. Run web application:")
    print("   python app.py")
    print("\n6. Access application:")
    print("   http://localhost:5000")
    print("\n" + "="*60)


def main():
    """Main setup function"""
    print("="*60)
    print("Maritime IDS Project Setup")
    print("="*60)
    
    if not check_python_version():
        print("\n⚠ Warning: Python version may be incompatible")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    create_directories()
    create_env_file()
    create_readme_notice()
    print_next_steps()


if __name__ == "__main__":
    main()

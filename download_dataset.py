"""
NSL-KDD Dataset Downloader
Automatically downloads the NSL-KDD dataset from multiple mirror sources
"""

import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Dataset sources (in order of preference)
DATASET_SOURCES = [
    {
        'name': 'GitHub - defcom17/NSL_KDD',
        'train_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
        'test_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt'
    },
    {
        'name': 'GitHub - jmnwong/NSL-KDD-Dataset',
        'train_url': 'https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain+.txt',
        'test_url': 'https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest+.txt'
    },
    {
        'name': 'GitHub - vinayakumarr/Network-Intrusion-Detection',
        'train_url': 'https://raw.githubusercontent.com/vinayakumarr/Network-Intrusion-Detection/master/NSL-KDD/KDDTrain+.txt',
        'test_url': 'https://raw.githubusercontent.com/vinayakumarr/Network-Intrusion-Detection/master/NSL-KDD/KDDTest+.txt'
    }
]

def download_file(url, destination, filename):
    """Download a file from URL to destination with progress"""
    print(f"  Downloading {filename}...", end=' ')
    try:
        def progress_hook(count, block_size, total_size):
            if total_size > 0:
                percent = int(count * block_size * 100 / total_size)
                sys.stdout.write(f"\r  Downloading {filename}... {percent}%")
                sys.stdout.flush()
        
        urllib.request.urlretrieve(url, destination, progress_hook)
        print(f"\r  ✅ Downloaded {filename} successfully!")
        return True
    except Exception as e:
        print(f"\r  ❌ Failed to download {filename}: {str(e)}")
        return False

def verify_file(filepath):
    """Verify downloaded file is valid"""
    if not os.path.exists(filepath):
        return False
    
    # Check file size (NSL-KDD train should be ~20MB, test ~5MB)
    size = os.path.getsize(filepath)
    if size < 1000:  # Less than 1KB is likely an error page
        return False
    
    # Check first line contains expected format
    try:
        with open(filepath, 'r') as f:
            first_line = f.readline()
            # Should have comma-separated values
            if ',' in first_line and len(first_line) > 50:
                return True
    except:
        pass
    
    return False

def main():
    print("=" * 70)
    print("NSL-KDD Dataset Downloader")
    print("=" * 70)
    
    # Create data directory
    data_dir = Path('data/raw')
    data_dir.mkdir(parents=True, exist_ok=True)
    
    train_file = data_dir / 'KDDTrain+.txt'
    test_file = data_dir / 'KDDTest+.txt'
    
    # Check if files already exist
    if train_file.exists() and test_file.exists():
        print("\n📁 Dataset files already exist!")
        print(f"   - {train_file}")
        print(f"   - {test_file}")
        
        if verify_file(train_file) and verify_file(test_file):
            print("\n✅ Files verified successfully!")
            print("\nYou can now run: python train.py")
            return
        else:
            print("\n⚠️  Existing files appear corrupted. Re-downloading...")
            train_file.unlink(missing_ok=True)
            test_file.unlink(missing_ok=True)
    
    # Try each source
    for i, source in enumerate(DATASET_SOURCES, 1):
        print(f"\n📥 Attempting download from source {i}/{len(DATASET_SOURCES)}")
        print(f"   Source: {source['name']}")
        
        # Download training set
        train_success = download_file(source['train_url'], train_file, 'KDDTrain+.txt')
        if not train_success:
            continue
        
        # Verify training set
        if not verify_file(train_file):
            print("  ⚠️  Training file verification failed")
            train_file.unlink(missing_ok=True)
            continue
        
        # Download test set
        test_success = download_file(source['test_url'], test_file, 'KDDTest+.txt')
        if not test_success:
            train_file.unlink(missing_ok=True)
            continue
        
        # Verify test set
        if not verify_file(test_file):
            print("  ⚠️  Test file verification failed")
            train_file.unlink(missing_ok=True)
            test_file.unlink(missing_ok=True)
            continue
        
        # Success!
        print(f"\n🎉 Success! Dataset downloaded from {source['name']}")
        print(f"\n📊 Dataset Information:")
        print(f"   Training set: {train_file} ({os.path.getsize(train_file) / 1024 / 1024:.2f} MB)")
        print(f"   Test set:     {test_file} ({os.path.getsize(test_file) / 1024 / 1024:.2f} MB)")
        print(f"\n✅ Dataset ready! You can now run: python train.py")
        return
    
    # All sources failed
    print("\n" + "=" * 70)
    print("❌ Failed to download dataset from all sources")
    print("=" * 70)
    print("\n📝 Manual Download Instructions:")
    print("\n1. Visit one of these sources:")
    print("   - https://github.com/defcom17/NSL_KDD")
    print("   - https://www.kaggle.com/datasets/hassan06/nslkdd")
    print("   - https://github.com/jmnwong/NSL-KDD-Dataset")
    print("\n2. Download these files:")
    print("   - KDDTrain+.txt")
    print("   - KDDTest+.txt")
    print(f"\n3. Place them in: {data_dir.absolute()}")
    print("\n4. Then run: python train.py")
    
    sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Download interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {str(e)}")
        sys.exit(1)

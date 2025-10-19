import os
import subprocess
import sys

def setup_project():
    """Setup the project environment"""
    print("🚀 Setting up Evil Twin Detection System...")
    
    # Create directories
    os.makedirs('data', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    print("Directories created")
    print("Installing dependencies...")
    
    # Install requirements
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("Dependencies installed")
    except subprocess.CalledProcessError:
        print("Failed to install dependencies")
        print("Try: pip install -r requirements.txt")
        print("\n Setup complete!")
    print("\nNext steps:")
    print("1. Ensure your dataset is at 'data/cic_evil_twin_processed.csv'")
    print("2. Run: streamlit run app.py")
    print("3. Go to 'Model Training' page and train the models")
    print("4. Start scanning for Evil Twin networks!")

if __name__ == "__main__":
    setup_project()
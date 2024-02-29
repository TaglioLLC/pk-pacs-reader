import subprocess
import sys

def install_packages(requirements_path='requirements.txt'):
    """Install packages listed in the given requirements file using pip."""

    python_executable = sys.executable

    # Run pip install for each requirement
    subprocess.check_call([python_executable, '-m', 'pip', 'install', '-r', requirements_path])
   

if __name__ == '__main__':
    try:
        install_packages()
        print("\nSuccess!")
    except Exception as e:
        print(f"\nError: {e}")
    
    input("Press enter to continue...")

import ctypes
import sys
import os

def is_admin():
    
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin(attempt):

    new_attempt = attempt + 1
    script = os.path.abspath(sys.argv[0])

    args = [arg for arg in sys.argv[1:] if not arg.startswith('--attempt=')]
    params = ' '.join(args)
    if params:
        cmd = f'"{script}" {params} --attempt={new_attempt}'
    else:
        cmd = f'"{script}" --attempt={new_attempt}'
    
    ctypes.windll.shell32.ShellExecuteW(
        None,         
        "runas",       
        sys.executable,
        cmd,           
        None,          
        1              
    )
    sys.exit()


def main():
    
    attempt = 1
    for arg in sys.argv[1:]:
        if arg.startswith('--attempt='):
            try:
                attempt = int(arg.split('=')[1])
            except ValueError:
                pass
            break

    if not is_admin():
        if attempt >= 3:
            print("over 3 attempts")
            input("Enter")
            sys.exit(1)
        else:
            print(f"Running as admin... {attempt}")
            run_as_admin(attempt)
    else:
        print("Program ran with admin privileges.")
        input("Press Enter to exit...")
        sys.exit(0)

if __name__ == "__main__":
    main()
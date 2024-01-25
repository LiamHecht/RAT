use std::process::{Command, exit};

static FILENAME: &str = "client.pyw";


#[cfg(target_os = "windows")]
fn install_python() {
    let url = "https://www.python.org/ftp/python/3.9.5/python-3.9.5-amd64.exe";
    let filename = "python_installer.exe";

    let output = Command::new("powershell")
        .args(&["-Command", &(format!("Invoke-WebRequest -Uri {} -OutFile {}", url, filename))])
        .output().expect("Failed to download the python installer.");

    if !output.status.success() {
        eprintln!("Failed to download the python installer.");
        exit(1);
    }

    let output = Command::new(filename)
        .output().expect("Failed to execute the python installer.");

    if !output.status.success() {
        eprintln!("Failed to execute the python installer.");
        exit(1);
    }

    std::fs::remove_file(filename).expect("Failed to remove the installer file.");
}

fn install_client() {
    let url = "http://localhost:8000/";

    let output = Command::new("powershell")
    .args(&["-Command", &(format!("Invoke-WebRequest -Uri {} -OutFile {}", url, FILENAME))])
    .output().expect("Failed to download the client.");
    let output = Command::new("powershell")
    .args(&["-Command", &(format!("Invoke-WebRequest -Uri {} -OutFile client_requirements.txt", url))])
    .output().expect("Failed to download the client requirements.");


    if !output.status.success() {
        eprintln!("Failed to download the client.");
        exit(1);
    }
}
fn run_python_script() {
    let mut child = Command::new("powershell")
    .args(&["-Command", &(format!("python {}", FILENAME))])
    .spawn()
    .expect("Failed to execute PowerShell command.");
}

fn install_requirements() {
    let mut child = Command::new("powershell")
    .args(&["-Command", &(format!("python -m pip install -r client_requirements.txt"))])
    .output()
    .expect("Failed to execute PowerShell command.");
    std::fs::remove_file("client_requirements.txt").expect("Failed to remove the client_requirements.txt.");
}



fn main() {
    // install_client()
}


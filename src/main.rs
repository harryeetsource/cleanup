use std::env;
use std::process::{ Command, ExitStatus, Stdio };
use log::{ debug, error, info, trace, warn };
use crossterm::execute;
use crossterm::style::{ Color, ResetColor, SetForegroundColor };
use std::fs::OpenOptions;
use std::io::{ self, Read };
use regex::Regex;
use std::io::{ BufRead, BufReader };
use winapi::um::processthreadsapi::GetCurrentThread;
use core::ffi::c_ulong;
use core::ptr;
use winapi::um::winnt::HANDLE;
const THREAD_SUSPEND_COUNT: c_ulong = 0x0000000A;
#[derive(Debug)]
struct SystemCommand<'a> {
    program: &'a str,
    args: Vec<&'a str>,
}
use std::error::Error;
use std::thread;
fn exec_command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|child| child.wait_with_output())
        .map_err(|e| format!("Failed to start '{}': {}", program, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Log the output
    log::info!("{}: {}", program, stdout);
    if !stderr.is_empty() {
        log::error!("{}: {}", program, stderr);
    }

    // Print to console
    println!("{}", stdout);
    if !stderr.is_empty() {
        eprintln!("{}", stderr);
    }

    if output.status.success() {
        Ok(())
    } else {
        Err(
            format!(
                "'{}' with arguments {:?} failed with exit code {:?}: {}",
                program,
                args,
                output.status.code(),
                stderr
            )
        )
    }
}
fn execute_commands(commands: &[SystemCommand], error_messages: &mut Vec<String>) {
    for command in commands {
        if let Err(e) = exec_command(command.program, &command.args) {
            error_messages.push(format!("Error executing {:?}: {}", command, e));
        }
    }
}

fn perform_disk_cleanup(error_messages: &mut Vec<String>) {
    trace!("Performing disk cleanup.");
    let disk_cleanup_command = vec![SystemCommand {
        program: "cleanmgr",
        args: vec!["/sagerun:1"],
    }];
    execute_commands(&disk_cleanup_command, error_messages);
}
fn cleanup_prefetch_files(system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Deleting Prefetch files.");
    let prefetch_path = format!("{}\\Prefetch\\*", system_root);
    let remove_prefetch_command_str =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", prefetch_path);
    let prefetch_cleanup_command = vec![SystemCommand {
        program: "powershell",
        args: vec!["-command", &remove_prefetch_command_str],
    }];
    execute_commands(&prefetch_cleanup_command, error_messages);
}

fn cleanup_windows_update_cache(system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Cleaning up Windows Update cache.");
    let windows_update_command_str = format!(
        "rd /s /q {}",
        system_root.to_owned() + "\\SoftwareDistribution"
    );
    let windows_update_cleanup_commands = vec![
        SystemCommand { program: "cmd", args: vec!["/c", &windows_update_command_str] },
        SystemCommand { program: "net", args: vec!["stop", "wuauserv"] },
        SystemCommand { program: "net", args: vec!["stop", "bits"] },
        SystemCommand { program: "net", args: vec!["start", "wuauserv"] },
        SystemCommand { program: "net", args: vec!["start", "bits"] }
    ];
    execute_commands(&windows_update_cleanup_commands, error_messages);
}
fn remove_temporary_files(temp: &str, system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Removing temporary files.");

    let temp_files_pattern = format!("{}\\*", temp);
    let temp_system_pattern = format!("{}\\temp\\*", system_root);

    let temp_files_command =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", temp_files_pattern);
    let temp_system_command =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", temp_system_pattern);

    let delete_temp_commands = vec![
        SystemCommand { program: "powershell", args: vec!["-command", &temp_files_command] },
        SystemCommand { program: "powershell", args: vec!["-command", &temp_system_command] }
    ];

    execute_commands(&delete_temp_commands, error_messages);
}

fn cleanup_font_cache(system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Cleaning up font cache.");
    let font_cache_path =
        format!("{}\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*", system_root);
    let font_cache_system_path =
        format!("{}\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*", system_root);

    let remove_font_cache_command =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", font_cache_path);
    let remove_font_cache_system_command =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", font_cache_system_path);

    let font_cache_cleanup_commands = vec![
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Stop-Service -Name 'fontcache' -Force"],
        },
        SystemCommand { program: "powershell", args: vec!["-command", &remove_font_cache_command] },
        SystemCommand {
            program: "powershell",
            args: vec!["-command", &remove_font_cache_system_command],
        },
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Start-Service -Name 'fontcache'"],
        }
    ];
    execute_commands(&font_cache_cleanup_commands, error_messages);
}

fn disable_insecure_windows_features(error_messages: &mut Vec<String>) {
    trace!("Disabling insecure windows features.");
    let windows_feature_disable_commands = vec![
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/disable-feature", "/featurename:WindowsMediaPlayer"],
        },
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/disable-feature", "/featurename:SMB1Protocol"],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                "/v",
                "fDenyTSConnections",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
                "/v",
                "fAllowToGetHelp",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "/v",
                "NoDriveTypeAutoRun",
                "/t",
                "REG_DWORD",
                "/d",
                "255",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                "/v",
                "EnableMulticast",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f"
            ],
        }
    ];
    execute_commands(&windows_feature_disable_commands, error_messages);
}
fn enable_uac(error_messages: &mut Vec<String>) {
    trace!("Enable UAC");
    let enable_uac_commands = vec![
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "/v",
                "EnableLUA",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "/v",
                "ConsentPromptBehaviorAdmin",
                "/t",
                "REG_DWORD",
                "/d",
                "2",
                "/f"
            ],
        }
    ];
    execute_commands(&enable_uac_commands, error_messages);
}
fn delete_old_log_files(error_messages: &mut Vec<String>) {
    trace!("Deleting log files older than 7 days");
    let delete_log_files_command = vec![SystemCommand {
        program: "forfiles",
        args: vec![
            "/p",
            "C:\\Windows\\Logs",
            "/s",
            "/m",
            "*.log",
            "/d",
            "-7",
            "/c",
            "cmd /c del @path"
        ],
    }];
    execute_commands(&delete_log_files_command, error_messages);
}
fn enable_credential_guard(error_messages: &mut Vec<String>) {
    trace!("Enabling Credential Guard.");
    let enable_credential_guard_commands = vec![
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA",
                "/v",
                "LsaCfgFlags",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f"
            ],
        },
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", "{bootmgr}", "loadoptions", "DISABLE-LSA-ISO,DISABLE-VSM"],
        },
        SystemCommand {
            program: "bcdedit",
            args: vec![
                "/set",
                "{bootmgr}",
                "device",
                "path",
                "\\EFI\\Microsoft\\Boot\\SecConfig.efi"
            ],
        }
    ];
    execute_commands(&enable_credential_guard_commands, error_messages);
}
fn enable_secure_boot(error_messages: &mut Vec<String>) {
    trace!("Enabling Secure Boot");
    let secure_boot_init = vec![
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", "{default}", "bootmenupolicy", "Standard"],
        },
        /*
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", "{globalsettings}", "custom:16000075", "true"],
        },
        */
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", "{bootmgr}", "path", "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"],
        }
    ];
    execute_commands(&secure_boot_init, error_messages);
}
fn enable_exploit_protection_settings(error_messages: &mut Vec<String>) {
    trace!("Enabling Exploit Protection settings");
    let exploit_protection_command = vec![SystemCommand {
        program: "powershell",
        args: vec!["-command", "Set-ProcessMitigation -System -Enable DEP,SEHOP"],
    }];
    execute_commands(&exploit_protection_command, error_messages);
}
fn enable_address_space_layout_randomization(error_messages: &mut Vec<String>) {
    trace!("Enabling Address Space Layout Randomization.");
    let aslr_command = vec![SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
            "/v",
            "MoveImages",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f"
        ],
    }];
    execute_commands(&aslr_command, error_messages);
}
fn optimize_system(error_messages: &mut Vec<String>) {
    trace!("Optimizing system.");
    let clear_recycle_bin_command = "Clear-RecycleBin -Confirm:$false -Force";

    let optimization_commands = vec![
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Optimize-Volume -DriveLetter C -Defrag -ReTrim"],
        },
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Optimize-Volume -DriveLetter C -Retrim"],
        },
        SystemCommand { program: "bcdedit", args: vec!["/set", "bootux", "disabled"] },
        SystemCommand {
            program: "powershell",
            args: vec!["-command", clear_recycle_bin_command],
        }
    ];
    execute_commands(&optimization_commands, error_messages);
}

fn disable_office_macros(error_messages: &mut Vec<String>) {
    trace!("Disabling Microsoft Office macros by default");
    let macro_disable_commands = vec![
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKCU\\Software\\Microsoft\\Office\\16.0\\Excel\\Security",
                "/v",
                "VBAWarnings",
                "/t",
                "REG_DWORD",
                "/d",
                "4",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKCU\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security",
                "/v",
                "VBAWarnings",
                "/t",
                "REG_DWORD",
                "/d",
                "4",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security",
                "/v",
                "VBAWarnings",
                "/t",
                "REG_DWORD",
                "/d",
                "4",
                "/f"
            ],
        }
    ];
    execute_commands(&macro_disable_commands, error_messages);
}
fn enable_windows_defender_realtime_protection(error_messages: &mut Vec<String>) {
    trace!("Enabling Windows Defender Realtime Protection Features");
    let windows_def_rt_protection = vec![
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                "/v",
                "DisableAntiSpyware",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "/v",
                "DisableBehaviorMonitoring",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "/v",
                "DisableOnAccessProtection",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "/v",
                "DisableScanOnRealtimeEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f"
            ],
        }
    ];
    execute_commands(&windows_def_rt_protection, error_messages);
}
fn restrict_lsa_access(error_messages: &mut Vec<String>) {
    trace!("Restricting LSA access");
    let lsa_commands = vec![
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "/v",
                "RestrictAnonymous",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization",
                "/v",
                "DODownloadMode",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f"
            ],
        },
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\",
                "/v",
                "Enabled",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f"
            ],
        },
        SystemCommand { program: "bcdedit", args: vec!["/set", "kstackguardpolicy", "enable"] },
        SystemCommand { program: "sc", args: vec!["config", "wscsvc", "start=", "auto"] },
        SystemCommand { program: "sc", args: vec!["start", "wscsvc"] },
        SystemCommand { program: "powershell", args: vec!["Update-MpSignature"] }
    ];
    execute_commands(&lsa_commands, error_messages);
}
fn fix_components(error_messages: &mut Vec<String>) {
    trace!("Checking for system file componentstore corruption");
    let sfc_commands = vec![
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/cleanup-image", "/startcomponentcleanup"],
        },
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/cleanup-image", "/startcomponentcleanup", "/resetbase"],
        },
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/cleanup-image", "/restorehealth"],
        },
        SystemCommand { program: "sfc", args: vec!["/scannow"] }
    ];

    execute_commands(&sfc_commands, error_messages);
}
fn enable_secure_boot_step_2(error_messages: &mut Vec<String>) {
    trace!("Enabling secure boot-step 2.");
    let secure_boot_step_2_command = vec![SystemCommand {
        program: "powershell",
        args: vec!["-command", "Confirm-SecureBootUEFI"],
    }];
    execute_commands(&secure_boot_step_2_command, error_messages);
}
fn update_drivers(error_messages: &mut Vec<String>) {
    trace!("Checking for signed driver updates");
    let driver_update_command = vec![SystemCommand {
        program: "powershell",
        args: vec![
            "-command",
            "Get-WmiObject Win32_PnPSignedDriver | foreach { $infPath = Get-ChildItem -Path C:\\Windows\\INF -Filter $_.InfName -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName; if ($infPath) { Invoke-Expression ('pnputil /add-driver ' + $infPath + ' /install') } }"
        ],
    }];
    execute_commands(&driver_update_command, error_messages);
}
fn enable_full_memory_dumps(error_messages: &mut Vec<String>) {
    trace!("Enabling full memory dumps.");

    let enable_dump_command =
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'CrashDumpEnabled' -Value 1";
    let set_dump_file_command =
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'DumpFile' -Value 'C:\\Windows\\MEMORY.DMP'";

    let registry_commands = vec![
        SystemCommand { program: "powershell", args: vec!["-command", enable_dump_command] },
        SystemCommand { program: "powershell", args: vec!["-command", set_dump_file_command] }
    ];

    execute_commands(&registry_commands, error_messages);
}
fn disable_ipv6(error_messages: &mut Vec<String>) {
    trace!("Disabling IPv6 on all interfaces.");
    let disable_ipv6_command_str =
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' -Name 'DisabledComponents' -Value 0xFF";
    let disable_ipv6_command = vec![SystemCommand {
        program: "powershell",
        args: vec!["-command", disable_ipv6_command_str],
    }];
    execute_commands(&disable_ipv6_command, error_messages);
}
fn bootloader(error_messages: &mut Vec<String>) {
    trace!("Securing Windows Bootloader");
    // Retrieve the bootloader GUID
    let bootloader_guid_result = get_bootloader_guid();

    let bootloader_guid = match bootloader_guid_result {
        Ok(guid) => guid,
        Err(e) => {
            error_messages.push(format!("Failed to get bootloader GUID: {}", e));
            return;
        }
    };

    // Convert the bootloader GUID to a borrowed str (&str) for the lifetime of the call
    let guid_str = bootloader_guid.as_str();

    // Prepare commands, temporarily converting String arguments to &str within the same scope
    let loader_commands = vec![
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", guid_str, "integritychecks", "on"],
        },
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", guid_str, "hypervisoriommupolicy", "enable"],
        },
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", guid_str, "hypervisorlaunchtype", "auto"],
        },
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", guid_str, "bootintegrityservices", "enable"],
        },
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", guid_str, "elamdrivers", "enable"],
        },
        SystemCommand{
            program: "bcdboot",
            args: vec!["C:\\windows", "/m", guid_str],
        },
        SystemCommand {
            program: "bcdedit",
            args: vec!["/set", guid_str, "nx", "AlwaysOn"]
        }
    ];

    execute_commands(&loader_commands, error_messages);
}
fn harden_system(error_messages: &mut Vec<String>) {
let harden_commands = vec![
    SystemCommand {
        program: "netsh",
        args: vec!["advfirewall", "set", "allprofiles", "state", "on"],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry",
            "/v",
            "Start",
            "/t",
            "REG_DWORD",
            "/d",
            "4",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "/v",
            "SMB2",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ],
    },
    SystemCommand {
        program: "powershell",
        args: vec![
            "-command",
            "Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
            "/v",
            "UseLogonCredential",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation",
            "/v",
            "SecureFirmwareUpdate",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config",
            "/v",
            "AnnounceFlags",
            "/t",
            "REG_DWORD",
            "/d",
            "5",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
            "/v",
            "NtlmMinClientSec",
            "/t",
            "REG_DWORD",
            "/d",
            "537395200",
            "/f",
        ],
    },
    
    SystemCommand {
    program: "reg",
    args: vec![
        "add",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        "/v",
        "ClearPageFileAtShutdown",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
        ],
    },
    SystemCommand {
    program: "reg",
    args: vec![
        "add",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg",
        "/f",
        "/t",
        "REG_DWORD",
        "/v",
        "AllowedPaths",
        "/d",
        "System\\CurrentControlSet\\Control",
    ],
    },

    
    SystemCommand {
        program: "wevtutil",
        args: vec!["sl", "Security", "/ca:O:BAG:SYD:(A;;0x7;;;BA)(A;;0x7;;;SO)"],
    }
    
    ];
    execute_commands(&harden_commands, error_messages);
}
fn disable_hibernation(){
    let disable_hibernation = SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power",
            "/v",
            "HibernateEnabled",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ],
    };

    // Since `exec_command` requires a slice, we convert args to a slice
    let program = disable_hibernation.program;
    let args = disable_hibernation.args;

    match exec_command(program, &args) {
        Ok(_) => println!("Hibernation disabled successfully."),
        Err(e) => eprintln!("Failed to disable hibernation: {}", e),
    }
}
fn setup_logging() -> Result<(), fern::InitError> {
    fern::Dispatch
        ::new()
        // Format the logs
        .format(|out, message, record| {
            out.finish(
                format_args!(
                    "{}[{}][{}] {}",
                    chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                    record.target(),
                    record.level(),
                    message
                )
            )
        })
        // Add stdout logger
        .chain(std::io::stdout())
        // Add file logger
        .chain(OpenOptions::new().write(true).create(true).append(true).open("output.log")?)
        // Apply the configuration
        .apply()?;

    Ok(())
}

fn get_bootloader_guid() -> Result<String, Box<dyn Error>> {
    let output = Command::new("bcdedit")
        .args(&["/enum", "all"])
        .stdout(Stdio::piped())
        .spawn()?
        .stdout.ok_or("Could not capture standard output.")?;

    let reader = BufReader::new(output);
    let re = Regex::new(r"identifier\s+\{([0-9a-fA-F-]+)\}")?;
    let mut is_windows_boot_loader_section = false;

    for line in reader.lines() {
        let line = line?;

        if line.contains("Windows Boot Loader") {
            is_windows_boot_loader_section = true;
        } else if line.contains("identifier") && is_windows_boot_loader_section {
            if let Some(caps) = re.captures(&line) {
                return caps.get(1)
                           .map(|m| m.as_str().to_string())
                           .ok_or_else(|| "Failed to extract GUID.".into());
            }
        }
    }

    Err("No GUID found for Windows Boot Loader in bcdedit output.".into())
}
/*
fn rename_pc(error_messages: &mut Vec<String>) {
    let powershell_script = r#"
    # Get the serial number from the BIOS
    $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber

    # Get memory form factors (12: SODIMM, typical for laptops)
    $memoryFormFactors = (Get-WmiObject -Class Win32_PhysicalMemory).FormFactor

    # Determine device type (Desktop or Laptop) based on memory form factor
    $deviceType = "DKP"
    if (12 -in $memoryFormFactors) {
        $deviceType = "LPT"
    }

    # Define the new computer name based on device type
    $newName = "GLT-$deviceType-$serialNumber"

    # Rename the computer
    Rename-Computer -NewName $newName -Force -Restart
    "#;

    // Format the PowerShell script as a command-line argument
    let script_argument = format!("-Command {}", powershell_script);

    // Use `exec_command` to execute the PowerShell script
    if let Err(e) = exec_command("powershell", &[&script_argument]) {
        error_messages.push(format!("Error renaming PC: {}", e));
    }
}
*/
fn disable_games(error_messages: &mut Vec<String>){
    let game_script = r#"
    # Enhanced PowerShell script to disable/uninstall gaming features and services at HKLM level

# Run as Administrator


# Define a function to safely remove apps by package name
function Remove-AppxPackageByName {
    param (
        [string]$PackageName
    )
    Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*$PackageName*" } | ForEach-Object {
        Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        Write-Output "Removed package: $($_.PackageFullName)"
    }
}

# Uninstall Xbox services and apps for all users
"Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.Xbox.TCUI", "Microsoft.XboxSpeechToTextOverlay" | ForEach-Object {
    Remove-AppxPackageByName -PackageName $_
}

# Uninstall common Microsoft Store games for all users
"Microsoft.SolitaireCollection", "Microsoft.MicrosoftMahjong", "Microsoft.MinecraftUWP" | ForEach-Object {
    Remove-AppxPackageByName -PackageName $_
}

# Registry changes for disabling Game Bar and Game Mode for all users
$registryPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameBar"
)

foreach ($path in $registryPaths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameBar" -Name "AllowGameBar" -Value 0

# Stop and Disable Gaming Services for all users
$serviceNames = @("XboxGipSvc", "XboxNetApiSvc")
foreach ($name in $serviceNames) {
    Get-Service $name | ForEach-Object {
        Stop-Service $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service $_.Name -StartupType Disabled
        Write-Output "Service disabled: $name"
    }
}

# Optional: Remove Game Bar features completely from the system
Get-WindowsCapability -Online | Where-Object Name -like "*App.GamingServices*" | Remove-WindowsCapability -Online

# Output status
Write-Output "System-wide gaming features and services have been disabled/uninstalled."

    "#;
    // Format the PowerShell script as a command-line argument
    let script_argument = format!("-Command {}", game_script);
    // Use `exec_command` to execute the PowerShell script
    if let Err(e) = exec_command("powershell", &[&script_argument]) {
        error_messages.push(format!("Error disabling gaming services: {}", e));
    }
}

fn is_thread_suspended(thread_handle: HANDLE) -> bool {
    let mut suspend_count: c_ulong = 0;

    let status = unsafe {
        ntapi::ntpsapi::NtQueryInformationThread(
            thread_handle,
            THREAD_SUSPEND_COUNT,
            &mut suspend_count as *mut c_ulong as *mut _,
            std::mem::size_of_val(&suspend_count) as u32,
            ptr::null_mut(),
        )
    };

    status == 0 && suspend_count > 0
}
fn main() -> Result<(), String> {
    if let Err(e) = setup_logging() {
        eprintln!("Error setting up logging: {}", e);
        let _ = Ok::<bool, ()>(false);
    }
    execute!(std::io::stdout(), SetForegroundColor(Color::Magenta)).unwrap();
    let system_root = env::var("SYSTEMROOT").expect("Failed to get system root");
    let temp = env::var("TEMP").expect("Failed to get temp directory");
    let mut error_messages: Vec<String> = Vec::new();
    let handle = thread::spawn( move || {
    // Execute initial series of commands
    fix_components(&mut error_messages);
    cleanup_prefetch_files(&system_root, &mut error_messages);
    cleanup_windows_update_cache(&system_root, &mut error_messages);
    perform_disk_cleanup(&mut error_messages);
    disable_games(&mut error_messages);
    remove_temporary_files(&temp, &system_root, &mut error_messages);
    cleanup_font_cache(&system_root, &mut error_messages);
    disable_insecure_windows_features(&mut error_messages);
    enable_uac(&mut error_messages);
    delete_old_log_files(&mut error_messages);
    enable_credential_guard(&mut error_messages);
    enable_exploit_protection_settings(&mut error_messages);
    enable_secure_boot(&mut error_messages);
    enable_secure_boot_step_2(&mut error_messages);
    disable_office_macros(&mut error_messages);
    enable_address_space_layout_randomization(&mut error_messages);
    enable_windows_defender_realtime_protection(&mut error_messages);
    restrict_lsa_access(&mut error_messages);
    optimize_system(&mut error_messages);
    disable_hibernation();
    update_drivers(&mut error_messages);
    enable_full_memory_dumps(&mut error_messages);
    disable_ipv6(&mut error_messages);
    bootloader(&mut error_messages);
    harden_system(&mut error_messages);
    //rename_pc(&mut error_messages);

    // Handle errors
    let _ = execute!(std::io::stdout(), ResetColor);
    if !error_messages.is_empty() {
        for error_message in error_messages {
            error!("Error: {}", error_message);
        }
        return Err("Some tasks failed".to_string());
    }
    Ok(())
});

let current_thread = unsafe { GetCurrentThread() };
    if is_thread_suspended(current_thread) {
        unsafe {
            ntapi::ntpsapi::NtResumeThread(current_thread, ptr::null_mut());
        }
    }
    let _ = handle.join().unwrap();
    Ok(())
}

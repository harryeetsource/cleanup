use std::env;
use std::process::{ Command, ExitStatus, Stdio };
use log::{ debug, error, info, trace, warn };
use crossterm::execute;
use crossterm::style::{ Color, ResetColor, SetForegroundColor };
use std::fs::OpenOptions;
use std::io::{ self, Read };
struct SystemCommand<'a> {
    program: &'a str,
    args: Vec<&'a str>,
}

fn exec_command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(| child| child.wait_with_output())
        .map_err(|e| format!("Failed to execute '{}': {}", program, e))?;

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
        Err(format!("'{}' failed with exit code: {:?}", program, output.status.code()))
    }
}
fn execute_commands(commands: &[SystemCommand], error_messages: &mut Vec<String>) {
    for command in commands {
        if let Err(e) = exec_command(command.program, &command.args) {
            error_messages.push(e);
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
    let prefetch_command_str = format!("del /s /q /f {}\\Prefetch\\*", system_root);
    let prefetch_cleanup_command = vec![SystemCommand {
        program: "cmd",
        args: vec!["/c", &prefetch_command_str],
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
    let temp_files = format!("{}\\*", temp);
    let temp_system = format!("{}\\temp\\*", system_root);
    let delete_temp_commands = vec![
        SystemCommand { program: "del", args: vec!["/s", "/q", &temp_files] },
        SystemCommand { program: "del", args: vec!["/s", "/q", &temp_system] }
    ];
    execute_commands(&delete_temp_commands, error_messages);
}

fn cleanup_font_cache(system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Cleaning up font cache.");
    let font_cache_path =
        format!("{}\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*", system_root);
    let font_cache_system_path =
        format!("{}\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*", system_root);
    let font_cache_cleanup_commands = vec![
        SystemCommand { program: "net", args: vec!["stop", "fontcache"] },
        SystemCommand { program: "del", args: vec!["/f", "/s", "/q", "/a", &font_cache_path] },
        SystemCommand {
            program: "del",
            args: vec!["/f", "/s", "/q", "/a", &font_cache_system_path],
        },
        SystemCommand { program: "net", args: vec!["start", "fontcache"] }
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
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
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
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
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
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
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
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
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
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
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
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
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
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA",
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
            args: vec![
                "/set",
                "{0cb3b571-2f2e-4343-a879-d86a476d7215}",
                "loadoptions",
                "DISABLE-LSA-ISO,DISABLE-VSM"
            ],
        },
        SystemCommand {
            program: "bcdedit",
            args: vec![
                "/set",
                "{0cb3b571-2f2e-4343-a879-d86a476d7215}",
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
    let secure_boot_init = vec![SystemCommand {
        program: "bcdedit",
        args: vec!["/set", "{default}", "bootmenupolicy", "Standard"],
    }];
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
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
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
    let optimization_commands = vec![
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Optimize-Volume -DriveLetter C -Defrag -ReTrim"],
        },
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Optimize-Volume -DriveLetter C -Retrim"],
        },
        SystemCommand { program: "defrag", args: vec!["C:", "/0"] },
        SystemCommand { program: "bcdedit", args: vec!["/set", "bootux", "disabled"] }
    ];
    execute_commands(&optimization_commands, error_messages);
}
fn enable_data_execution_prevention(error_messages: &mut Vec<String>) {
    trace!("Enabling Data Execution Prevention (DEP)");
    let dep_command = vec![SystemCommand {
        program: "bcdedit",
        args: vec!["/set", "nx", "AlwaysOn"],
    }];
    execute_commands(&dep_command, error_messages);
}
fn disable_office_macros(error_messages: &mut Vec<String>) {
    trace!("Disabling Microsoft Office macros by default");
    let macro_disable_commands = vec![
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security",
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
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security",
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
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security",
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
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
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
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
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
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
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
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
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
    let recycle_bin = format!("{}\\$Recycle.Bin", std::env::var("systemdrive").unwrap());
    let lsa_commands = vec![
        SystemCommand {
            program: "reg",
            args: vec![
                "add",
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
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
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization",
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
        SystemCommand { program: "rd", args: vec!["/s /q", &recycle_bin] },
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
fn main() -> Result<(), String> {
    if let Err(e) = setup_logging() {
        eprintln!("Error setting up logging: {}", e);
        let _ = Ok::<bool, ()>(false);
    }
    execute!(std::io::stdout(), SetForegroundColor(Color::Magenta)).unwrap();
    let system_root = env::var("SYSTEMROOT").expect("Failed to get system root");
    let temp = env::var("TEMP").expect("Failed to get temp directory");
    let mut error_messages: Vec<String> = Vec::new();
    // Execute initial series of commands

    cleanup_prefetch_files(&system_root, &mut error_messages);
    cleanup_windows_update_cache(&system_root, &mut error_messages);
    perform_disk_cleanup(&mut error_messages);

    remove_temporary_files(&temp, &system_root, &mut error_messages);
    cleanup_font_cache(&system_root, &mut error_messages);
    disable_insecure_windows_features(&mut error_messages);
    enable_uac(&mut error_messages);
    delete_old_log_files(&mut error_messages);
    enable_credential_guard(&mut error_messages);
    enable_exploit_protection_settings(&mut error_messages);
    enable_data_execution_prevention(&mut error_messages);
    enable_secure_boot(&mut error_messages);
    enable_secure_boot_step_2(&mut error_messages);
    disable_office_macros(&mut error_messages);
    enable_address_space_layout_randomization(&mut error_messages);
    enable_windows_defender_realtime_protection(&mut error_messages);
    restrict_lsa_access(&mut error_messages);
    optimize_system(&mut error_messages);
    fix_components(&mut error_messages);
    update_drivers(&mut error_messages);
    // Handle errors
    let _ = execute!(std::io::stdout(), ResetColor);
    if !error_messages.is_empty() {
        for error_message in error_messages {
            error!("Error: {}", error_message);
        }
        return Err("Some tasks failed".to_string());
    }

    Ok(())
}

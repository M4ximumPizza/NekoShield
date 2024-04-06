# NekoShield - Advanced Malware Scanning Tool

NekoShield is a sophisticated Java application designed to scan and detect malicious code signatures in JAR files. It is specifically 
designed to combat the notorious `fractureiser` virus that has been found in several Minecraft projects uploaded to CurseForge and 
BukkitDev. The malware is embedded in multiple mods, some of which were added to highly popular modpacks. The malware is known to 
target Windows and Linux systems.

## The Threat - fractureiser

`fractureiser` is a dangerous virus that, if left unchecked, can cause significant harm to your machine. It is embedded within various 
Minecraft mods and is known to target Windows and Linux systems. The virus was named `fractureiser` after the CurseForge account that 
uploaded the most notable malicious files.

The `fractureiser` virus operates in two stages:

1. **Stage 1**: The virus embeds itself within various Minecraft mods. When these mods are installed and run, the virus is activated. It targets Windows and Linux systems, embedding itself within the system's files.

2. **Stage 2**: Once embedded, the virus identifies suspicious files in specific locations. On Windows, it checks the `Microsoft Edge` folder and the `Startup` folder for specific malicious files. On Linux, it checks for a specific malicious file in the `~/.config/.data/` directory.

The virus is particularly dangerous because it can remain dormant and undetected on a system until it is activated. Once activated, it 
can cause significant harm to the system, including data loss and system instability.

NekoShield is designed to scan and detect the signatures of this virus in JAR files, providing a means to identify and remove the threat 
before it can cause harm.

## Features
- **Multi-threaded Malware Scanning**: NekoShield utilizes multiple threads for parallel scanning of JAR files, improving speed and efficiency.
- **Detailed Malware Detection**: NekoShield scans for known malicious code signatures, including those of `fractureiser`, and performs additional checks for potential threats.
- **Scan Cancellation**: NekoShield provides functionality to cancel a running scan.
- **User-friendly Interface**: NekoShield offers a straightforward command-line interface for initiating scans and viewing results.
- **Detailed Logging**: If a threat is detected, the application logs the path of the infected JAR file and the nature of the threat.
- **Stage 2 Detection**: NekoShield checks for stage 2 of the malware infection, identifying suspicious files in specific locations.

## Usage
1. Compile the source files:

``` javac -cp src src/mi/m4x/project/nekoshield/NekoShield.java src/mi/m4x/project/nekoshield/Detector.java ```

2. Run the main class:
```java -cp src mi.m4x.project.nekoshield.NekoShield <number_of_threads> <directory_to_scan> <emit_walk_errors> ```
   Replace `<number_of_threads>` with the number of threads to use for scanning, `<directory_to_scan>` with the directory to scan, and `<emit_walk_errors>` with a boolean value indicating whether to emit errors when walking the directory tree.

3. Follow the prompts to initiate the scan and view the results.

## Additional Tasks
- **Perform Stage 2 Check**: NekoShield checks for stage 2 of the malware infection, identifying suspicious files in specific locations.

### LICENSE

This project is under the MIT LICENSE - see the [LICENSE](LICENSE.txt) file for details.
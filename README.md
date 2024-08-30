# IPTables-Best-Rules

## Optimal IPTables Configuration for Attack Mitigation

This project is dedicated to crafting the most effective IPTables configurations to defend against a wide range of cyber attacks. Our focus is on analyzing threats, developing custom rules for prevention, and ensuring system security—all while maintaining optimal performance and minimizing false positives.

## 🔧 Dependencies

- **Iptables**: `v1.8.7+`
- **xtables-addons-common**: `v3.19-1ubuntu1+`

## 🛡️ Required xtables Modules

- **`xt_psd`**: Port Scan Detection - Detects port scans and mitigates potential threats.
- **`xt_recent`**: Connection Tracking - Monitors and manages recent connections, helping to track and prevent repeated attack attempts.
- **`xt_string`**: String Matching - Identifies and filters packets based on specific strings, such as those found in DNS queries, to block malicious traffic.

## 🚀 Features

- Comprehensive protection against various attack vectors:
  - SYN flood protection
  - Port scan detection and prevention
  - Protection against invalid packets and TCP flag combinations
  - Rate limiting for SSH connections
  - ICMP flood protection
  - DNS amplification attack mitigation
  - ARP spoofing prevention
  - DDoS attack mitigation
- Automatic dependency checking and installation
- Multiple iptables version support
- Configurable port acceptance
- Local traffic allowance
- Basic firewall configuration with advanced security rules
- Logging of dropped packets for analysis

## 📥 How to Use

1. **Clone the Repository**

   ```git clone https://github.com/PietroCavaliere/Iptables-Best-Rules.git```  
   ```cd Iptables-Best-Rules```

2. **Make the Script Executable**

   ```chmod +x iptables-rules.sh```

3. **Run the Script**

   ```sudo ./iptables-rules.sh```

4. **Follow the On-Screen Prompts**

   - The script will check for dependencies and install them if necessary.
   - You'll be prompted to select an iptables version if multiple are found.
   - You can choose to reset existing iptables configurations.
   - Enter the ports you want to accept connections on.
   - Decide whether to load basic firewall configurations.

5. **Review the Applied Rules**

   - After the script completes, you can review the applied rules by running:

   ```sudo iptables -L -v```

6. **Save the Rules (Optional)**

   - To make the rules persistent across reboots, you can save them:

   ```sudo iptables-save > /etc/iptables/rules.v4```

   - Note: The exact command might vary depending on your Linux distribution.

## ⚠️ Caution

- Always test these rules in a controlled environment before applying them to production systems.
- Some configurations might interfere with legitimate traffic. Be prepared to adjust rules as needed for your specific use case.
- Regularly update and review your firewall rules to maintain optimal security.

## 🤝 Contributing

Contributions to improve and expand this project are welcome! Please feel free to submit pull requests or open issues for discussion.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

By using this configuration, you're taking a significant step towards enhancing your system's security against various cyber threats while maintaining optimal performance.

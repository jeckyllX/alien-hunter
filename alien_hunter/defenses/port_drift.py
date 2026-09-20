"""
Port Drift and Baseline Anomaly Tracker.
Monitors trusted devices for unexpected newly opened ports or services,
detecting compromised IoT devices, malware infections, and backdoors.
"""

from typing import Dict, List, Optional, Set, Any


class PortDriftTracker:
    """Detects service and port discrepancies against trusted baseline configurations."""

    HIGH_RISK_PORTS = {
        "21/FTP": "Unencrypted File Transfer",
        "22/SSH": "Remote Shell Access",
        "23/Telnet": "Insecure Remote Shell / Mirai Vector",
        "445/SMB": "Windows File Sharing / Worm Vector",
        "3389/RDP": "Remote Desktop Protocol",
        "5555/ADB": "Android Debug Bridge Remote Root",
        "5900/VNC": "Virtual Network Computing",
    }

    @classmethod
    def check_device_drift(
        cls,
        ip: str,
        mac: str,
        display_name: str,
        current_open_ports: List[str],
        whitelist_entry: Optional[Dict[str, Any]] = None,
        cached_baseline: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Compares currently discovered open ports against the device's baseline.
        Returns warning or critical alerts if new unauthorized ports have opened.
        """
        threats: List[str] = []
        mac_upper = mac.upper()

        # Determine expected baseline ports:
        # 1. Explicitly declared in known_devices.json ("ports" or "baseline_ports")
        # 2. Or cached from initial discovery
        baseline: Optional[Set[str]] = None
        if whitelist_entry:
            raw_ports = whitelist_entry.get("ports") or whitelist_entry.get("baseline_ports")
            if raw_ports is not None:
                # Normalize ports e.g. "80", "80/HTTP", 80
                baseline = set()
                for p in raw_ports:
                    p_str = str(p)
                    baseline.add(p_str)
                    # Add port number prefix if formatted like "80/HTTP"
                    if "/" in p_str:
                        baseline.add(p_str.split("/")[0])

        if baseline is None and cached_baseline is not None:
            baseline = set(cached_baseline)

        # If no baseline established, nothing to drift from yet
        if baseline is None:
            return threats

        current_set = set(current_open_ports)
        # Find new ports that are not in baseline (checking both full tag "80/HTTP" and port number "80")
        new_ports: List[str] = []
        for cp in current_set:
            port_num = cp.split("/")[0] if "/" in cp else cp
            if cp not in baseline and port_num not in baseline:
                new_ports.append(cp)

        if not new_ports:
            return threats

        # Evaluate risk level of new ports
        critical_new_ports = []
        standard_new_ports = []

        for np in new_ports:
            is_critical = False
            for high_risk_tag, risk_desc in cls.HIGH_RISK_PORTS.items():
                hr_num = high_risk_tag.split("/")[0]
                if np == high_risk_tag or np.startswith(f"{hr_num}/"):
                    critical_new_ports.append(f"{np} ({risk_desc})")
                    is_critical = True
                    break
            if not is_critical:
                standard_new_ports.append(np)

        baseline_display = ", ".join(sorted(list(baseline))) if baseline else "None"

        if critical_new_ports:
            threats.append(
                f"CRITICAL: High-Risk Port Drift on {display_name} ({ip})! "
                f"Newly exposed critical service(s): {', '.join(critical_new_ports)}. "
                f"Baseline was: [{baseline_display}]. Potential host compromise, backdoor, or malware infection!"
            )
        elif standard_new_ports:
            threats.append(
                f"WARNING: Port Drift detected on {display_name} ({ip})! "
                f"Newly opened port(s): {', '.join(standard_new_ports)} (Baseline: [{baseline_display}])."
            )

        return threats

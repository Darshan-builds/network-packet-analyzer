# 🧪 Testing Guide

This guide helps you test the Advanced Network Packet Analyzer to ensure everything works correctly.

## 📋 Pre-Testing Checklist

Before testing, ensure:
- [x] Python 3.8+ is installed
- [x] All dependencies are installed (`pip install -r requirements.txt`)
- [x] You have root/sudo access
- [x] Network interface is available and active
- [x] You are on an authorized network

## 🚦 Quick Functionality Tests

### Test 1: Installation Verification

```bash
# Check Python version
python3 --version  # Should be 3.8 or higher

# Check dependencies
python3 -c "import scapy; import rich; print('✓ Dependencies OK')"

# Check script
python3 packet_analyzer.py --version
# Expected output: Advanced Network Packet Analyzer v2.0.0

# List interfaces
sudo python3 packet_analyzer.py --list-interfaces
# Should show available network interfaces
```

**Expected Result:** All commands run without errors

---

### Test 2: Basic Capture (10 seconds)

```bash
# Capture 50 packets with timeout
sudo timeout 10 python3 packet_analyzer.py -c 50 --pcap --csv
```

**Expected Result:**
- Dashboard appears showing packet capture
- Real-time packet table updates
- Statistics panel shows protocols
- After completion, files saved in `captures/` directory
- Output shows "Capture Summary" with statistics

**Verify:**
```bash
ls -lh captures/
# Should show .pcap and .csv files
```

---

### Test 3: Protocol Detection

Test each protocol separately:

**TCP Traffic:**
```bash
# Generate TCP traffic
curl -s http://example.com > /dev/null &

# Capture
sudo timeout 5 python3 packet_analyzer.py -f "tcp" -c 20 --pcap
```

**UDP Traffic (DNS):**
```bash
# Generate DNS queries
nslookup google.com &
nslookup github.com &

# Capture
sudo timeout 5 python3 packet_analyzer.py -f "udp port 53" -c 10 --csv
```

**ICMP Traffic:**
```bash
# Generate ICMP in background
ping -c 10 8.8.8.8 > /dev/null &

# Capture
sudo timeout 5 python3 packet_analyzer.py -f "icmp" -c 10 --pcap
```

**Expected Result:** 
- Each protocol is correctly identified in dashboard
- Protocol column shows: TCP, UDP, DNS, ICMP

---

### Test 4: BPF Filters

Test various filter expressions:

```bash
# Test 1: Port filter
sudo timeout 5 python3 packet_analyzer.py -f "tcp port 80" -c 10

# Test 2: Host filter  
sudo timeout 5 python3 packet_analyzer.py -f "host 8.8.8.8" -c 10

# Test 3: Combined filter
sudo timeout 5 python3 packet_analyzer.py -f "tcp and port 443" -c 10

# Test 4: Exclusion filter
sudo timeout 5 python3 packet_analyzer.py -f "not arp" -c 20
```

**Expected Result:** Only packets matching filter are captured

---

### Test 5: Intrusion Detection System

**Test Port Scan Detection:**

```bash
# Terminal 1: Start IDS monitoring
sudo python3 packet_analyzer.py --ids --alerts -q -c 200 -o captures/ids_test &

# Terminal 2: Simulate port scan (safe, localhost only)
for port in {1..30}; do nc -zv -w 1 localhost $port 2>&1 | grep -v "refused"; done

# Wait for completion
wait

# Check for alerts
cat captures/ids_test/alert_report_*.txt
```

**Expected Result:**
- PORT_SCAN alert is triggered
- Alert report contains detection details
- Source IP and scanned ports are logged

**Test DoS Detection:**

```bash
# Terminal 1: Start monitoring
sudo python3 packet_analyzer.py --ids --alerts -q -c 1000 &

# Terminal 2: Generate high packet rate
ping -f -c 1000 localhost  # May require root

# Check alerts
```

**Expected Result:** DoS alert triggered if threshold exceeded

---

### Test 6: Output Formats

```bash
# Capture with all output formats
sudo python3 packet_analyzer.py -c 50 --pcap --csv --json -o captures/format_test

# Verify files exist
ls -lh captures/format_test/
```

**Expected Files:**
- `capture_*.pcap` - Binary packet capture
- `capture_*.csv` - Comma-separated values
- `capture_*.json` - JSON format

**Verify CSV:**
```bash
head -5 captures/format_test/capture_*.csv
# Should show: timestamp,protocol,src_ip,dst_ip,src_port,dst_port,length,flags,info
```

**Verify JSON:**
```bash
head -20 captures/format_test/capture_*.json
# Should show valid JSON array
python3 -m json.tool captures/format_test/capture_*.json > /dev/null && echo "✓ Valid JSON"
```

**Verify PCAP:**
```bash
# Using tcpdump
tcpdump -r captures/format_test/capture_*.pcap -c 5
# Or using Wireshark (if installed)
wireshark captures/format_test/capture_*.pcap
```

---

### Test 7: Performance & Statistics

```bash
# Run 30-second capture
sudo timeout 30 python3 packet_analyzer.py --pcap -o captures/performance_test
```

**Verify in output:**
- Total packets captured
- Packets per second rate
- Average packet size
- Protocol distribution
- Top conversations
- Bandwidth metrics (Mbps/Kbps)
- Active sessions count

**Expected Result:** 
- Statistics are accurate
- Performance metrics calculated correctly
- No memory warnings or errors

---

### Test 8: Session Reconstruction

Generate TCP sessions and verify tracking:

```bash
# Terminal 1: Start capture
sudo python3 packet_analyzer.py --ids -c 100 -o captures/session_test &

# Terminal 2: Generate HTTP connections
curl http://example.com > /dev/null
curl http://github.com > /dev/null
curl http://google.com > /dev/null

# Wait for completion
wait
```

**Check output for:**
- Active TCP Sessions section
- Session keys showing IP:port pairs
- Packet counts per session
- Session states (ESTABLISHED, CLOSED, etc.)

---

### Test 9: Dashboard UI

Test dashboard rendering:

```bash
# Start with dashboard
sudo python3 packet_analyzer.py -c 100

# While running, observe:
# - Packet table updates in real-time
# - Statistics panel refreshes
# - Protocol colors display correctly
# - No rendering glitches
# - Ctrl+C stops gracefully
```

**Expected Result:**
- Clean, readable dashboard
- Real-time updates smooth
- No text overlap
- Colors display correctly
- Graceful exit on Ctrl+C

---

### Test 10: Quiet Mode

```bash
# Run in quiet mode
sudo python3 packet_analyzer.py -q -c 100 --pcap --csv

# Should show:
# - Initial info messages
# - Progress indicator (packets captured)
# - Final summary
# - No dashboard
```

**Expected Result:**
- No live dashboard displayed
- Progress updates shown
- Final summary printed
- Files saved correctly

---

## 🔍 Advanced Testing

### Stress Test

Test with high packet rates:

```bash
# Generate traffic
ping -f localhost &  # Fast ping
curl -s http://example.com > /dev/null &
nslookup google.com &

# Capture for 60 seconds
sudo timeout 60 python3 packet_analyzer.py -c 5000 --pcap

# Check results
```

**Monitor:**
- CPU usage (should be reasonable)
- Memory usage (check for leaks)
- Packet drop rate
- File sizes

---

### Long-Running Test

```bash
# 5-minute capture
sudo timeout 300 python3 packet_analyzer.py --ids --alerts --pcap --csv -o captures/long_test
```

**Verify:**
- No crashes or errors
- Memory doesn't grow indefinitely
- All packets processed
- Statistics accurate
- Files saved correctly

---

### Multi-Interface Test

If you have multiple interfaces:

```bash
# List interfaces
sudo python3 packet_analyzer.py --list-interfaces

# Test each interface
sudo timeout 10 python3 packet_analyzer.py -i eth0 -c 50
sudo timeout 10 python3 packet_analyzer.py -i wlan0 -c 50
```

---

## ✅ Test Results Checklist

After running all tests, verify:

| Test | Status | Notes |
|------|--------|-------|
| Installation | ✓ / ✗ | All dependencies installed |
| Basic capture | ✓ / ✗ | Packets captured successfully |
| Protocol detection | ✓ / ✗ | TCP/UDP/ICMP/DNS/HTTP detected |
| BPF filters | ✓ / ✗ | Filters work correctly |
| IDS port scan | ✓ / ✗ | Port scans detected |
| IDS DoS | ✓ / ✗ | High packet rates detected |
| PCAP output | ✓ / ✗ | Valid PCAP files created |
| CSV output | ✓ / ✗ | Valid CSV files created |
| JSON output | ✓ / ✗ | Valid JSON files created |
| Statistics | ✓ / ✗ | Accurate stats calculated |
| Session tracking | ✓ / ✗ | TCP sessions tracked |
| Dashboard | ✓ / ✗ | UI renders correctly |
| Quiet mode | ✓ / ✗ | Non-interactive mode works |
| Performance | ✓ / ✗ | Good performance, no leaks |
| Long-running | ✓ / ✗ | Stable over time |

---

## 🐛 Common Issues & Solutions

### Issue: "Permission denied"
**Solution:** Run with sudo: `sudo python3 packet_analyzer.py`

### Issue: "No packets captured"
**Solution:** 
- Check interface: `ip link show`
- Generate traffic: `ping 8.8.8.8`
- Try without filter first

### Issue: "Dashboard not updating"
**Solution:**
- Check terminal size (minimum 80x24)
- Update rich: `pip install --upgrade rich`
- Try quiet mode: `-q`

### Issue: "Import errors"
**Solution:**
```bash
pip install --upgrade scapy rich
# Or reinstall
pip uninstall scapy rich
pip install scapy rich
```

### Issue: "High CPU usage"
**Solution:**
- Use BPF filters to reduce packet volume
- Limit packet count: `-c 1000`
- Use quiet mode: `-q`

---

## 📊 Performance Benchmarks

Expected performance on typical hardware:

| Metric | Expected Value |
|--------|---------------|
| Packets/second | 1,000 - 10,000 |
| CPU usage | 10-30% single core |
| Memory usage | 50-200 MB |
| Dashboard refresh | 2 FPS |
| Capture latency | < 1ms |

---

## 🔬 Unit Testing (Optional)

If you want to add unit tests:

```python
# tests/test_analyzer.py
import pytest
from packet_analyzer import PacketAnalyzer, Config

def test_config_values():
    """Test configuration constants"""
    assert Config.VERSION == "2.0.0"
    assert Config.MAX_PACKETS > 0
    
def test_packet_analyzer():
    """Test packet analyzer instantiation"""
    analyzer = PacketAnalyzer()
    assert analyzer is not None

# Run tests
# pytest tests/test_analyzer.py -v
```

---

## 📝 Test Report Template

```markdown
# Test Report

**Date:** 2024-11-01
**Tester:** Your Name
**Environment:** Ubuntu 22.04, Python 3.10
**Version:** 2.0.0

## Summary
- Total Tests: 10
- Passed: 9
- Failed: 1
- Skipped: 0

## Failed Tests
- Test #6: JSON output - Missing field in output

## Notes
- Dashboard performance excellent
- IDS detection accurate
- No memory leaks observed
- Files saved correctly

## Recommendation
✓ Ready for release after fixing Test #6
```

---

## 🎯 Testing Best Practices

1. **Test on clean system** - Use VM or container
2. **Test different OSes** - Ubuntu, Fedora, Arch
3. **Test different Python versions** - 3.8, 3.9, 3.10, 3.11
4. **Test with real traffic** - Not just localhost
5. **Test edge cases** - Empty captures, corrupted packets
6. **Test error handling** - Invalid filters, bad interfaces
7. **Document issues** - Create GitHub issues for bugs
8. **Verify fixes** - Re-test after bug fixes

---

## 🚀 Pre-Release Checklist

Before releasing to GitHub:

- [ ] All core tests pass
- [ ] No critical bugs
- [ ] Documentation accurate
- [ ] Examples work
- [ ] Performance acceptable
- [ ] No security issues
- [ ] License file present
- [ ] README complete

---

## 📧 Reporting Issues

If you find bugs during testing:

1. **Check existing issues** on GitHub
2. **Create detailed bug report** with:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment details
   - Error messages
   - Screenshots if applicable
3. **Label appropriately**: bug, enhancement, etc.

---

**Happy Testing! 🎉**

Remember: Thorough testing ensures a quality tool for the community!
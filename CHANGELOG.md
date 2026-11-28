# What's new in NetFinder

Short notes per version. The newest version is on top.
The app shows these after it updates itself, and the Release workflow uses them as the release notes.
Keep each line short and simple.

## 1.1.17
- Fixed: right-clicking a device showed "Current cell cannot be set to an invisible cell" instead of the menu.

## 1.1.16
- Scan starts with an empty list and shows only the devices that answer now. What was read from a device (model, serial, hardware) comes back when it answers.

## 1.1.15
- Export → PDF report: a ready PDF file of the devices shown, no browser needed.
- Watch devices (☰ menu, right-click, or "Watched" in the side menu): pick devices and how often; NetFinder pings them and tells you when one goes down or comes back. One small ping each time, so the network hardly notices.
- Risky open ports (Telnet, FTP, VNC, open databases…) show in red with what to do; "Risky ports" in the side menu lists those devices.

## 1.1.14
- The "Get models" and Windows login windows grow to fit their text, so nothing is cut off (also with bigger text or scaling in Windows).
- Columns, the side menu and the details pane also grow when Windows shows bigger text.

## 1.1.13
- New look: a side menu with the count of each kind of device (PCs, servers, cameras, printers…) and of each network.
- The selected device opens on the right: its model, how to open it, hardware with SSD / HDD and drive space, open ports.
- Dark mode: ☰ menu → Dark mode.
- A PC whose firewall blocks NetFinder shows "Firewall blocks it" in the list.

## 1.1.12
- PCs blocked by their firewall: the fix is now two netsh lines that work in Command Prompt (the old PowerShell line broke when pasted there).

## 1.1.11
- Every disk shows its size (also when the PC is read over port 445), for example "WD2002FYPS (HDD, 2 TB)".
- All drive letters with size and free space: C:, D:, E:…, each on its own line.
- PCs blocked by their firewall: NetFinder shows a one-line command to open it on that PC.

## 1.1.10
- Windows PCs: every hard disk is listed (SSD and HDD), each on its own line.
- The Log tab shows only the lines about the selected device. Untick the box to see everything.
- Get models also tries every Dell / HP / Lenovo device, and says why one could not be read (firewall, turned off…).

## 1.1.9
- Windows PCs: hard disks (model, size, SSD or HDD), drive C: size and free space, and the graphics card with its memory.
- They show under the model in the device panel, in All details, and in the Excel / CSV / HTML export.

## 1.1.8
- Windows models work in a domain: the user can be ALMADA\admin, admin@almada.local or almada.local\admin.
- If WMI is blocked by the firewall, the PC is read over file sharing (port 445) instead.
- A wrong password stops after one try, so the account is not locked.
- The Log tab shows the result for every PC, and a short summary at the end.
- Dell/HP devices with only web ports are no longer shown as "Windows PC".
- Fixed names showing as "*" and wrong models like "ProductAgent1.0".
- Virtual network cards (Hyper-V, VMware) are no longer scanned by default.

## 1.1.7
- The update bar no longer has a "What's new" link.
- After an update, NetFinder shows a short list of what changed.

## 1.1.6
- New Model column: the model is read from the device itself (no password needed).
- "Get models" asks every device, also on other IP ranges.
- Windows PCs: model, serial, CPU, RAM and Windows version with an admin login.
- Export to Excel, CSV or an HTML report (print it to PDF).

## 1.1.5
- Show the cameras of an NVR (Hikvision, Dahua) with their IP, model and status.
- An icon for every device type in the list.
- "Open" link on every row: web page, Remote Desktop, SSH, Telnet, Winbox…

## 1.1.4
- Npcap can be installed even when npcap.com is blocked (other site or a file you choose).

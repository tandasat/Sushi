Sushi
======

Sushi is a tiny, simple hypervisor based monitoring tool detecting and stopping
some of PatchGuard activities from Ring-1.

A related blog entry can be found here:
    http://standa-note.blogspot.ca/2015/08/writing-hypervisor-for-kernel-mode-code.html


Installation and Uninstallation
--------------------------------

Get an archive file for compiled files form this link:

   https://github.com/tandasat/Sushi/releases/latest

On the x64 platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type 
the following command, and then restart the system to activate the change:

    bcdedit /set {current} testsigning on

To install the driver, extract the archive file and use the 'sc' command. For 
installation:

    >sc create Sushi type= kernel binPath= C:\Users\user\Desktop\Sushi.sys
    >sc start Sushi

For uninstallation:

    >sc stop Sushi
    >sc delete Sushi

Note that the system must support the Intel VT-x technology to successfully
install the driver. See the blog entry for configuration of the virtual machine
if you are going to test with VMware.

Once you have installed the Sushi.sys, it logs interesting activities on 
C:\Windows\Sushi.log and DebugView when it occurred, or you can run 
SushiTest.exe and see its output is being changed.
![Basic Output](/img/basic_output.png)

Also, you can install ChangeMSR.sys in the same way as above to trigger more 
interesting activities (although you may get bug check 0x109 if you are unlucky
as this driver does not handle all possible patterns).
![Detected](/img/detected.png)


Supported Platform(s)
----------------------
- Windows 8.1 and 10 (x64)


License
--------
This software is released under the MIT License, see LICENSE.

# SuperHID

SuperHID is a userspace solution for virtualizing input devices.  
Its original purpose is to virtualize digitizers, but any HID-compliant input device can be created.  

SuperHID works by implementing a USB backend that simulates the presence of a USB HID device (one per VM, and potentially more if needed).  
When a guest USB frontend driver probes that device, the backend forges answers to simulate a real USB HID device.  
The type of device is defined solely by the HID desciptor that hardcoded in SuperHID.

Once the device is up and ready in the guest, the backend will start getting polled for input events.  
SuperHID will pend those requests until it has some input events available.  
Input events can be fed to SuperHID using any (blocking) file descriptor. An easy way to test SuperHID is to use STDIN as a source for events.

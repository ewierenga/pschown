function chmod
{
    param ($rights, $file);
    $ownerRight = 0;
    $adminRight = 0;
    $everyRight = 0;
    $uname = $env:UserName;

    if ($rights -isnot [int]) { chelp; }
    if ($rights.ToString().Length -ne 3) { chelp; }

    else
    {
        $tempRights = $rights.ToString();

        for ($i = 0; $i -lt 3; $i = $i + 1)
        {
            if ([int]$tempRights.substring($i,1) -lt 0 -or [int]$tempRights.substring($i,1) -gt 7) { chelp; }
        }
    }

    if (-not [System.IO.File]::Exists($file)) { chelp; }

    # Now we can set the rights. I feel like the quickest way would be to go though each octal, and associate rights based 
    # on what is applicable to that... 
    #
    # 0: None
    # 1: Read and Execute
    # 2: Write
    # 3: Write
    # 4: Read
    # 5: Read and Execute
    # 6: Modify
    # 7: Full Control
   
    # OWNER
    Switch ($rights.ToString()[0])
    {
        "0" {}
        "1" {}
        "2" {}
        "3" {}
        "4" {}
        "5" {}
        "6" {}
        "7" {}
    }

    # USERS
    Switch ($rights.ToString()[1])
    {
        "0" { (_RemoveCurrentRules "everyone" "$file"); }
        "1" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "ExecuteFile" "allow" "$file"); }
        "2" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "write" "allow" "$file"); }
        "3" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "write" "allow" "$file"); (_AddAccessRule "everyone" "ExecuteFile" "allow" "$file"); }
        "4" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "read" "allow" "$file"); }
        "5" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "ReadAndExecute" "allow" "$file");}
        "6" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "Read" "allow" "$file"); (_AddAccessRule "everyone" "Write" "allow" "$file");}
        "7" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "fullcontrol" "allow" "$file");}
    }

    # EVERYONE
    Switch ($rights.ToString()[2])
    {
        "0" { (_RemoveCurrentRules "everyone" "$file"); }
        "1" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "ExecuteFile" "allow" "$file"); }
        "2" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "write" "allow" "$file"); }
        "3" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "write" "allow" "$file"); (_AddAccessRule "everyone" "ExecuteFile" "allow" "$file"); }
        "4" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "read" "allow" "$file"); }
        "5" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "ReadAndExecute" "allow" "$file");}
        "6" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "Read" "allow" "$file"); (_AddAccessRule "everyone" "Write" "allow" "$file");}
        "7" { (_RemoveCurrentRules "everyone" "$file"); (_AddAccessRule "everyone" "fullcontrol" "allow" "$file");}
    }


   
}

function _AddAccessRule ($objectRule, $permRule, $adRule, $_file)
{
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($objectRule,$permRule,$adRule)
    $acl = Get-Acl $_file
    $acl.AddAccessRule($rule)
    Set-Acl -Path $_file -AclObject $acl
}

function _RemoveCurrentRules ($objectRule, $_file)
{
    # This creates a blank template. It will remove anything that has FullControll, thus removing perms entirely.
    $ar = New-Object System.Security.AccessControl.FileSystemAccessRule("$objectRule", "FullControl","ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.RemoveAccessRuleAll($ar);
    Set-Acl -path $_file -AclObject $acl
}

function chelp
{
    "Here is the help function :)"
    break
}
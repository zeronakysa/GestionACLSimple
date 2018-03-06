function Show-Menu
 {
      param (
            [string]$Title = 'Choose action'
      )
      cls
      Write-Host "================ $Title ================"
      Write-Host "1: Press '1' to back-up an ACL ."
      Write-Host "2: Press '2' to modify an ACL."
      Write-Host "3: Press '3' to restore an ACL."
      Write-Host "4: Press '4' to view an ACL."
      Write-Host "Q: Press 'Q' to exit."
 }

 function Show-Modify-Menu
 {
      param (
            [string]$Title = 'Choose action'
      )
      cls
      Write-Host "================ $Title ================"
      Write-Host "1: Press '1' Delete simple permission."
      Write-Host "2: Press '2' Delete recurse permissions."
      Write-Host "3: Press '3' Modify simple permission."
      Write-Host "4: Press '4' Modify recurse permissions."
      Write-Host "5: Press '5' Add simple permission."
      Write-Host "6: Press '6' Add recurse permissions."
      Write-Host "Q: Press 'Q' to exit."
 }

 function Save
        #This is the backup function where you put your ACL in a CSV file
        # 1. Choose which folder to backup ACL from.
        # 2. Choose which folder to save CSV from 
        # 3. Export 
 {

    # Choose the folder to back-up ACL from
    'Please select a folder'
    $aclToSave = ($runApplication.BrowseForFolder(0, 'Select a folder', 0)).Self.Path
    if ($aclToSave -eq $Null){
        'Folder selection abort'
    return
    }

    # Choose the folder to save the CSV file
    'Please select where you want to save the ACL'
    $outputPath = ($runApplication.BrowseForFolder(0, 'Select a folder', 0)).Self.Path
    if ($outputPath -eq $Null){
        'Folder selection abort'
    return
    }

    # Choose the name for the CSV file
    $aclFileName = Read-Host "Please choose a name for your ACL file (without extension), if the file already exists, it will be erased."

    $outputFile = $outputPath + "\" + $aclFileName +"_Restore" +".csv"

    $acl = Get-Acl -Path $aclToSave
    $data = $acl.Access | Select-Object @{n='Path';e={ $aclToSave }}, IdentityReference, AccessControlType, InheritanceFlags, PropagationFlags, FileSystemRights

    $folders = Get-ChildItem $aclToSave -Recurse -Directory

    foreach ($folder in $folders) {
        $acl = Get-Acl -Path $folder.FullName
        $Path = $folder.FullName
        $data += $acl.Access | Select-Object @{n='Path';e={ $Path }}, IdentityReference, AccessControlType, InheritanceFlags, PropagationFlags, FileSystemRights
    }
    $data | Export-CSV -Path $outputFile -Encoding Unicode

    'ACL successfully save'
} 

function Restore

        #This is the restore of an ACL from a CSV file.
        # 1. Choose which folder to restore ACL from
        # 2. Choose the ACL CSV file to restore 
        # 3. Restore ACL
{
    'Please select your backup file'

    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    InitialDirectory = [Environment]::GetFolderPath('Desktop')
    }
    [void]$FileBrowser.ShowDialog()
    $FileBrowser.FileNames
    $filename = $FileBrowser.FileNames

    $par = Import-Csv -Path $filename
    foreach ( $i in $par ) { 
        $path= $i.Path
        $IdentityReference= $i.IdentityReference
        $AccessControlType=$i.AccessControlType
        $InheritanceFlags= $i.InheritanceFlags
        $PropagationFlags=$i.PropagationFlags
        $FileSystemRights=$i.FileSystemRights
        echo $path $IdentityReference
        $acl = Get-Acl $path
        $permission = $IdentityReference, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType
        $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        $acl | Set-Acl $path
    }
    'Restore complete'
}

 function Modify
 {
    $filePath = ($runApplication.BrowseForFolder(0, 'Select a folder', 0)).Self.Path
          if ($filePath -eq $Null){
          'Folder selection abort'
          return
          }
    
    Show-Modify-Menu
    view2($filePath)
    
    $input = Read-Host "Please make a selection"
      switch ($input)
      {
            '1' {
                 cls
                 'You chose option #1 - Remove Simple'
                 removeSimple($filePath)
            } '2' {
                 cls
                 'You chose option #2 - Remove Recurse'
                 removeRecurse($filePath)
            } '3' {
                 cls
                 'You chose option #3 - Modify Simple'
                 modifySimple($filePath)
            } '4' {
                 cls
                 'You chose option #4 - Modify Recurse'
                 modifyRecurse($filePath)
            } '5' {
                 cls
                 'You chose option #5 - Add Simple'
                 AddSimple($filePath)
            } '6' {
                 cls
                 'You chose option #6 - Add recurse'
                 AddRecurse($filePath)
            } 'q' {
                 return
            }
      }
 }

  function ModifySimple($filePath)
 {
    $user = Read-Host "Please spefify 'DOMAINE\USERNAME'"

    $perm = Read-Host "Please specify the permission to grant ('fullcontrol', 'write', 'read', 'readandexecute', 'modify'):"

    $control = Read-Host "Please specify the control acces  ('allow'/'deny') :"

    Get-Item ([string]$filePath) | ForEach-Object {
        $acl = Get-Acl -Path $_.FullName

        $rule=new-object System.Security.AccessControl.FileSystemAccessRule ($user, $perm, $control)

        $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $user
        } | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
            $acl.SetAccessRule($rule) | Out-Null
        }
        Set-Acl -Path $_.FullName -AclObject $acl
    }
    'Permission Successfuly edited'
 }

 function ModifyRecurse($filePath)
 {
    $user = Read-Host "Please spefify 'DOMAINE\USERNAME'"

    $perm = Read-Host "Please specify the permission to grant ('fullcontrol', 'write', 'read', 'readandexecute', 'modify'):"

    $control = Read-Host "Please specify the control acces  ('allow'/'deny') :"

    Get-Item ([string]$filePath) | ForEach-Object {
        $acl = Get-Acl -Path $_.FullName

        $rule=new-object System.Security.AccessControl.FileSystemAccessRule ($user, $perm, $control)

        $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $user
        } | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
            $acl.SetAccessRule($rule) | Out-Null
        }
        Set-Acl -Path $_.FullName -AclObject $acl

        $folders = Get-ChildItem ([string]$filePath) -Recurse -Directory

        foreach ($folder in $folders) {
            $acl = Get-Acl -Path $folder.FullName

            foreach ($access in $acl.Access) {
            if ($access.IdentityReference.Value -eq $user) {
                $acl.RemoveAccessRule($access) | Out-Null
            }
                $acl.SetAccessRule($rule) | Out-Null
            }
            Set-Acl -Path $folder.FullName -AclObject $acl
        }
    }
    'Permissions Successfuly edited'
 }

 function RemoveRecurse($filePath)
 {

    $user = Read-Host "Please spefify 'DOMAINE\USERNAME'."

     Get-Item ([string]$filePath) | ForEach-Object {
        $acl = Get-Acl -Path $_.FullName

        $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $user
        } | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
        }
        Set-Acl -Path $_.FullName -AclObject $acl
    }      

    $folders = Get-ChildItem ([string]$filePath) -Recurse -Directory

    foreach ($folder in $folders) {
        $acl = Get-Acl -Path $folder.FullName

        foreach ($access in $acl.Access) {
            if ($access.IdentityReference.Value -eq $user) {
                $acl.RemoveAccessRule($access) | Out-Null
            }
        }

        Set-Acl -Path $folder.FullName -AclObject $acl
    }
    'Permissions successfuly removed'
 }

  function RemoveSimple($filePath)
 {
    $user = Read-Host "Please spefify 'DOMAINE\USERNAME'"

    Get-Item ([string]$filePath) | ForEach-Object {
        $acl = Get-Acl -Path $_.FullName

        $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $user
        } | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
        }
        Set-Acl -Path $_.FullName -AclObject $acl
    }
    'Permission Successfuly deleted'
 }

 function AddSimple($filePath)
 {
    $user = Read-Host "Please spefify 'DOMAINE\USERNAME'"

    $perm = Read-Host "Please specify the permission to grant ('fullcontrol', 'write', 'read', 'readandexecute', 'modify'):"

    $control = Read-Host "Please specify the control acces  ('allow'/'deny') :"

    Get-Item ([string]$filePath) | ForEach-Object {
            $acl = Get-Acl -Path $_.FullName
            $rule=new-object System.Security.AccessControl.FileSystemAccessRule ($user, $perm, $control)
            $acl.Access | ForEach-Object {
            $acl.SetAccessRule($rule) | Out-Null
        }
        Set-Acl -Path $_.FullName -AclObject $acl
    }
    'Permission Successfuly added'
 }

 function AddRecurse($filePath)
 {

    $user = Read-Host "Please spefify 'DOMAINE\USERNAME'."

    $perm = Read-Host "Please specify the permission to grant ('fullcontrol', 'write', 'read', 'readandexecute', 'modify'):"

    $control = Read-Host "Please specify the control acces  ('allow'/'deny') :"

    $rule=new-object System.Security.AccessControl.FileSystemAccessRule ($user, $perm, $control)

    Get-Item ([string]$filePath) | ForEach-Object {
                $acl = Get-Acl -Path $_.FullName
                $acl.Access | ForEach-Object {
                $acl.SetAccessRule($rule) | Out-Null
            }
            Set-Acl -Path $_.FullName -AclObject $acl

        $folders = Get-ChildItem ([string]$filePath) -Recurse -Directory

        foreach ($folder in $folders) {
            $acl = Get-Acl -Path $folder.FullName

            foreach ($access in $acl.Access) {
                $acl.SetAccessRule($rule) | Out-Null
            }
            Set-Acl -Path $folder.FullName -AclObject $acl
        }
    }
    'Permissions Successfuly added'
 }

 function View
 {
  'Please select a folder'
      $aclToView = ($runApplication.BrowseForFolder(0, 'Select a folder', 0)).Self.Path
      if ($aclToView -eq $Null){
      'Folder selection abort'
      return
      }

      $Acl = Get-Acl $aclToView

      $viewResults = @()

      ForEach($Data in $Acl.Access){
          #$data
         $Properties = [ordered]@{'Group'=$Data.IdentityReference;
                                  'Permissions' = $Data.FileSystemRights;
                                  'AccessControl' = $Data.AccessControlType}
         $viewResults += New-Object -TypeName PSObject -Property $Properties
      }
      $viewResults | Out-Host
 }

  function View2($aclToView)
 {
      $Acl = Get-Acl ([string]$aclToView)

      $viewResults = @()

      ForEach($Data in $Acl.Access){
          #$data
         $Properties = [ordered]@{'Group'=$Data.IdentityReference;
                                  'Permissions' = $Data.FileSystemRights;
                                  'AccessControl' = $Data.AccessControlType}
         $viewResults += New-Object -TypeName PSObject -Property $Properties
      }
      $viewResults | Out-Host
 }

do
{
      $runApplication = New-Object -ComObject Shell.Application
      Show-Menu
      $input = Read-Host "Please make a selection"
      switch ($input)
      {
            '1' {
                 cls
                 'You chose option #1 - Back-up ACL'
                 Save
            } '2' {
                 cls
                 'You chose option #2 - Modify ACL'
                 Modify
            } '3' {
                 cls
                 'You chose option #3 - Restore ACL'
                 Restore
            } '4' {
                 cls
                 'You chose option #4 - View ACL'
                 View
                 
            } 'q' {
                 return
            }
      }
      $end = Read-Host "Press any key to continue..."
 }
until ($input -eq 'q')

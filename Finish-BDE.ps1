param ($NewPIN, $NewPassword, $CreateRecoveryPassword=$true, $CompanyIdentifier, [Switch]$NoHardwareTest, [Switch]$RmmTool, [Switch]$Verbose, [Switch]$Testing, [Switch]$DisplayCredential, [Switch]$TPMProtectorOnly, $BDEEncryptionMethod="AES256", [Switch]$SkipAdBackup)

	

#This function should be called after all prerequisites have been completed.
#It executes the BitLocker encryption process on the C: drive.
function Apply-BDE 
	{
		$pwAllowedKeyExistsTest = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorVariable fveKeyExistError -ErrorAction SilentlyContinue
			IF ($fveKeyExistError)
				{
					IF ($Verbose -eq $true)
						{
							Write-Output "Key Does not exist!!! Creating..."
						}
					$newKey = New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name FVE -Force
					#Since we didn't find the FVE key already, we won't be overwriting GP by setting these values. So go ahead and allow these Startup methods.
					$allowTpmOnly = New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name UseTPM -Value 2
					$allowTpmAndPin = New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name UseTPMPIN -Value 2
					$allowAdvancedStartup = New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name UseAdvancedStartup -Value 1
				}
		
		$bdeParams = @{
				
				MountPoint = "C:"
				EncryptionMethod = $BDEEncryptionMethod
				ErrorVariable = "bdeTpmErrors"
				WarningVariable = "bdeTpmWarnings"
				InformationVariable = "bdeTpmInfo"
				
			}
		
		$bdeRecoveryParams = @{
			
				MountPoint = "C:"
				RecoveryPasswordProtector = $true
				ErrorVariable = "bdeRecoveryErrors"
				WarningVariable = "bdeRecoveryWarnings"
				InformationVariable = "bdeRecoveryInfo"
				
			}
		
		$rmmToolParams = @{
				
				ErrorAction = "SilentlyContinue"
				WarningAction = "SilentlyContinue"
				
			}

		$noHardwareTestParams = @{
				
				SkipHardwareTest = $True
			
			}
		
		$tpmAndPinParams = @{
				
				PIN = $securePIN
				TPMAndPinProtector = $True
			}
		
		$passwordProtectorsParams = @{
				
				PasswordProtector = $True
				Password = $securePassword
			}
		
		IF ($RmmTool -eq $true)
			{
				$bdeParams = $bdeParams + $rmmToolParams
				$bdeRecoveryParams = $bdeRecoveryParams + $rmmToolParams
			}
		
		IF ($Testing -eq $true)
			{
				$bdeParams = $bdeParams + @{WhatIf = $true}
				$bdeRecoveryParams = $bdeRecoveryParams + @{WhatIf = $true}
			}
		
		IF ($NoHardwareTest -eq $True)
			{
				$bdeParams = $bdeParams + $noHardwareTestParams
			}
		
		IF ($tpmStatus)
			{
				$enhancedPinKeyExistsTest = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name UseEnhancedPin -ErrorVariable enhancedPinKeyExistsError -ErrorAction SilentlyContinue).UseEnhancedPin 
				IF ($enhancedPinKeyExistsTest -ne 1)
					{
						Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -Value 1 -Force -ErrorAction SilentlyContinue
					}
				
				IF ($TPMProtectorOnly -eq $true)
					{
						$bdeParams = $bdeParams + @{TPMProtector = $true}
						$DisplayCredential = $false
					}
					ELSE
					{
						$bdeParams = $bdeParams + $tpmAndPinParams
					}
			}
			ELSE
			{
				$bdeParams = $bdeParams + $passwordProtectorsParams
				#Since we detected that there's no TPM, the reg value to enable PasswordProtectors for OS drives needs to be validated
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EnableBDEWithNoTPM" -Value 1 -Force -ErrorAction SilentlyContinue
			}

		IF ($Verbose -eq $True)
			{
				Write-Output "Displaying bdeParams"
				$bdeParams
				Write-Output "Displaying bdeRecoveryParams"
				$bdeRecoveryParams					
			}
					
		IF ($SkipAdBackup -eq $true)
			{
				$key = New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name OSRequireActiveDirectoryBackup -Value 0 -PropertyType DWord -Force
				$key = New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name OSActiveDirectoryBackup -Value 0 -PropertyType DWord -Force
			}
		
		IF ($CreateRecoveryPassword -eq $true)
			{
				$recoveryPwExecute = Add-BitLockerKeyProtector @bdeRecoveryParams
				$doThis = Get-Date | out-file c:\windows\temp\Finish-BDE-recovery-errors.txt -append -ErrorAction SilentlyContinue
				$doThis = $bdeRecoveryErrors | out-file c:\windows\temp\Finish-BDE-recovery-errors.txt -append -ErrorAction SilentlyContinue
				$doThis = Get-Date | out-file c:\windows\temp\Finish-BDE-recovery-warnings.txt -append -ErrorAction SilentlyContinue
				$doThis = $bdeRecoveryWarnings | out-file c:\windows\temp\Finish-BDE-recovery-warnings.txt -append -ErrorAction SilentlyContinue
				$doThis = Get-Date | out-file c:\windows\temp\Finish-BDE-recovery-info.txt -append -ErrorAction SilentlyContinue
				$doThis = $bdeRecoveryInfo | out-file c:\windows\temp\Finish-BDE-recovery-info.txt -append -ErrorAction SilentlyContinue
			}
		
		$bdeExecute = Enable-BitLocker @bdeParams
			$doThis = Get-Date | out-file c:\windows\temp\Finish-BDE-TPM-errors.txt -append -ErrorAction SilentlyContinue
			$doThis = $bdeTpmErrors | out-file c:\windows\temp\Finish-BDE-TPM-errors.txt -append -ErrorAction SilentlyContinue
			$doThis = Get-Date | out-file c:\windows\temp\Finish-BDE-TPM-warnings.txt -append -ErrorAction SilentlyContinue
			$doThis = $bdeTpmWarnings | out-file c:\windows\temp\Finish-BDE-TPM-warnings.txt -append -ErrorAction SilentlyContinue
			$doThis = Get-Date | out-file c:\windows\temp\Finish-BDE-TPM-info.txt -append -ErrorAction SilentlyContinue
			$doThis = $bdeTpmInfo | out-file c:\windows\temp\Finish-BDE-TPM-info.txt -append -ErrorAction SilentlyContinue
			
		$doThis = Get-Date | out-file c:\windows\temp\Finish-BDE-params.txt -append -ErrorAction SilentlyContinue
		$doThis = $bdeParams | out-file c:\windows\temp\Finish-BDE-params.txt -append -ErrorAction SilentlyContinue
		$doThis = Get-Date | out-file c:\windows\temp\Finish-BDE-recovery-params.txt -append -ErrorAction SilentlyContinue
		$doThis = $bdeRecoveryParams | out-file c:\windows\temp\Finish-BDE-recovery-params.txt -append -ErrorAction SilentlyContinue
	}

#Get the serial number
$serial = (Get-CimInstance win32_bios).SerialNumber
$detectedPIN=($serial.Substring($serial.Length - 6)).ToUpper()

#IF NewPIN not provided detect and set it.
IF (!$NewPIN)
	{
		IF ($Verbose -eq $true)
			{
				Write-Output "NewPIN not provided... parsing first PIN from serial number..."
				Write-Output "Detected Serial Number is $serial."
			}
		$NewPIN = $detectedPIN
		
		IF ($Verbose -eq $true)
			{
				Write-Output "NewPIN is $NewPIN"
			}
	}


#Determine whether the TPM exists
$tpmStatus = (Get-TPM).TpmPresent


#If the TPM is present...
IF ($tpmStatus)
	{
		#IF NewPassword exists
		IF ($NewPassword)
			{
				Write-Output "NewPassword parameter was provided however the asset has an onboard TPM. Aborting."
				exit
			}
		#If NewPIN is at least 6 chars
		IF ($NewPin.length -ge 6)
			{
				IF ($Verbose -eq $true)
					{
						Write-Output "PIN is at least 6 characters in length."
					}
			}
			ELSE
				{
					Write-Output "NewPIN is not at least 6 characters in length!!!"
					exit
				}
		
		$securePIN = ConvertTo-SecureString $NewPIN -AsPlainText -Force
	}
	#If TPM is not present
	ELSE
		{
			IF ($Verbose -eq $true)
				{
					Write-Output "No TPM detected... verifying NewPassword..."
				}
			#If NewPassword doesn't exist, detect the NewPIN value. If longer than 5 chars, prepend CompanyIdentifier.
			IF (!$NewPassword)
				{
					#Just use NewPIN if its long enough
					IF ($Verbose -eq $true)
						{
							Write-Output "NewPassword not provided..."
						}
					IF (($NewPIN).length -ge 8)
						{
							IF ($Verbose -eq $true)
								{
									Write-Output "NewPIN is long enough to take the place of NewPassword... setting them equal."
								}
							$NewPassword = $NewPIN
						}
						ELSE
							{
							IF ($Verbose -eq $true)
								{
									Write-Output "NewPIN is not long enough to function as NewPassword..."
								}
							IF ($CompanyIdentifier)
								{
									$CompanyIdentifier = $CompanyIdentifier.toUpper()
									#Add CompanyIdentifier and NewPIN together to make NewPassword
									$NewPassword = $CompanyIdentifier + $NewPIN
									#Check that NewPassword is at least 8 chars
									IF (($NewPassword).length -ge 8)
										{
											IF ($Verbose -eq $true)
												{
													Write-Output "Successfully created NewPassword!!!"
													Write-Output "NewPassword is $NewPassword."
												}
										}
										ELSE
										{
											Write-Output "NewPassword is not long enough... Value is $NewPassword."
											exit
										}
								}
								ELSE
								{
									Write-Output "CompanyIdentifier not provided but required to create NewPassword... Exiting..."
									exit
								}
							}
				}
			$securePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
		}



Apply-BDE($tpmStatus,$NewPIN,$NewPassword,$verifiedOU,$CreateRecoveryPassword,$NoHardwareTest,$Testing,$TPMProtectorOnly,$BDEEncryptionMethod,$securePIN,$securePassword)


#Cleanup and output steps

#Show us the final credential if required
IF ($displayCredential -eq $true)
	{
		IF ($tpmStatus)
			{
				Write-Output "$NewPIN"
			}
			ELSE
				{
					Write-Output "$NewPassword"
				}
	}
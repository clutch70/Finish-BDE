########################################################################
#																		
#	Script Title: Finish-BDE											
#	Author: Brennan Custard												
#	Date: 8/26/2020														
#	Description: This script accepts basic parameters to complete		
#	the BDE process for a given OS disk in an endpoint.			 		
#																		
########################################################################
#
#	This script makes several assumptions.
#		1. The password or PIN must be at least 8 or 6 characters respectively.
#		2. If NewPIN is not specified, you want to use the last 6 of the 
#			serial number (all caps) as	the first PIN.
#		3. If NewPassword is not specified, you want to use a provided 
#			CompanyIdentifier paramater plus the last 6 of the serial
#			number (all caps) as the first password.
#		4. By default a RecoveryPasswordProtector should be added.
#		5. By default a hardware test will be performed before encryption
#
########################################################################


param ($NewPIN, $NewPassword, $CreateRecoveryPassword=$true, $CompanyIdentifier, $NoHardwareTest, $RmmTool=$false, $Verbose=$false, $Testing=$False, $DisplayCredential, $TPMProtectorOnly=$False, $BDEEncryptionMethod="AES256")

#IF ($NewPIN)
#	{
#		$securePIN = ConvertTo-SecureString $NewPIN -AsPlainText -Force
#	}
	
#IF ($NewPassword)
#	{
#		$securePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
#	}
#This function accepts an OU in Distinguished Name format and verifies whether
#the computer is currently a member of the provided OU, if so returns true.
#THIS FUNCTION DEPRACATED, BURDEN OF VERIFYING OU ASSIGNED TO RMM TOOL
	

#This function should be called after all prerequisites have been completed.
#It executes the BitLocker encryption process on the C: drive.
function Apply-BDE 
	{
		$bdeParams = @{
				
				MountPoint = "C:"
				EncryptionMethod = $BDEEncryptionMethod
				
			}
		
		$bdeRecoveryParams = @{
			
				MountPoint = "C:"
				RecoveryPasswordProtector = $true
				
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
				IF ($TPMProtectorOnly -eq $true)
					{
						$bdeParams = $bdeParams + @{TPMProtector = $true}
					}
					ELSE
					{
						$bdeParams = $bdeParams + $tpmAndPinParams
					}
			}
			ELSE
			{
				$bdeParams = $bdeParams + $passwordProtectorsParams
			}

		IF ($Verbose -eq $True)
			{
				IF ($tpmStatus)
					{
						Write-Output "Displaying bdeParams"
						$bdeParams
					}
					ELSE
					{
						Write-Output "Displaying bdeRecoveryParams"
						$bdeRecoveryParams					
					}
			}
		
		IF ($CreateRecoveryPassword -eq $true)
			{
				$recoveryPwExecute = Add-BitLockerKeyProtector @bdeRecoveryParams
			}
		
		$bdeExecute = Enable-BitLocker @bdeParams

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
				#Write-Output "PIN is at least 6 characters in length."
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
#OU detection, returns true if a workstation is a member of a specified parent OU
#$verifiedOU = Detect-OU($VerifyOU)

Apply-BDE($tpmStatus,$NewPIN,$NewPassword,$verifiedOU,$CreateRecoveryPassword,$NoHardwareTest,$Testing,$TPMProtectorOnly,$BDEEncryptionMethod,$securePIN,$securePassword)

#If VerifyOU was specified and verifiedOU is true, apply BDE
#IF (($VerifyOU) -and ($verifiedOU -eq $true))
#	{
#		
#	}

#If VerifyOU was not specified, apply BDE
#IF (!$VerifyOU)
#	{
#		Apply-BDE($tpmStatus,$NewPIN,$NewPassword,$verifiedOU,$CreateRecoveryPassword,$NoHardwareTest,$Testing)
#	}


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
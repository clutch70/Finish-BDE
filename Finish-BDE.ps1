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
#		1. The password or PIN must be 8 or 6 characters respectively.
#		2. If NewPIN is not specified, you want to use the last 6 of the 
#			serial number (all caps) as	the first PIN.
#		3. If NewPassword is not specified, you want to use a provided 
#			CompanyIdentifier paramater plus the last 6 of the serial
#			number (all caps) as the first password.
#		4. By default a RecoveryPasswordProtector should be added.
#		5. By default a hardware test will be performed before encryption
#
########################################################################


param ($NewPIN, $NewPassword, $VerifyOU, $CreateRecoveryPassword=$true, $CompanyIdentifier, $NoHardwareTest, $RmmTool=$false, $Verbose -eq $true=$false, $testing=$false)

#Er maybe not We need to set $verifiedOU to something so it can be set as a failure flag is something goes wrong
#$verifiedOU = $false

#This function accepts an OU in Distinguished Name format and verifies whether
#the computer is currently a member of the provided OU.
function Detect-OU 
	{

	IF (!$VerifyOU)
		{
			return
		}

	#Determine if the AD Module needs installing
	$modules = Get-Module -Name ActiveDirectory

	#If not exist install it
		IF (!$modules)
			{
				Import-Module -Name ActiveDirectory -Cmdlet Get-ADComputer, Get-ADOrganizationalUnit;
			}
			
			#Get the OU we're currently in
			#TODO make a try catch here in case we're not connected to the domain
			TRY
				{
					$Computer = Get-ADComputer $env:computername -ErrorAction Stop
				} CATCH
					{
						Write-Output "VerifyOU was provided but cannot get computer information from AD!!!"
						$verifiedOU = $false
						return
						
					}
			#Get the current OU of the AD computer
			$OU = $Computer.DistinguishedName.SubString($Computer.DistinguishedName.IndexOf('OU='));
			
			#Test if the OU we're in at least a child of VerifyOU
			IF ($OU -match $VerifyOU)
				{
					IF ($Verbose -eq $true)
						{
							Write-Output "Asset is in a child of the provided OU."
							Write-Output "Updating Group Policy..."
						}
					IF ($Testing -eq $false)
						{
							gpupdate
						}
						ELSE
						{
							Write-Output "Would execute gpupdate here, but that takes forever and the testing flag is set."
						}
					$verifiedOU = $true
					return($verifiedOU)
					
					#Write-Output "VerifyOU is $VerifyOU"
					#Write-Output "OU is $OU"
				}
				ELSE
				{
					Write-Output "Asset is NOT in a child of the provided OU!!! Exiting..."
					$verifiedOU = $false
					#Write-Output "VerifyOU is $VerifyOU"
					#Write-Output "OU is $OU"
					return($verifiedOU)

				}
	}
	

#This function should be called after all prerequisites have been completed.
#It executes the BitLocker encryption process on the C: drive.
function Apply-BDE 
	{
		IF ($VerifyOU)
			{
				IF ($verifiedOU -eq $false)
					{
						Write-Output "Aborting Apply-BDE funciton because verifiedOU was set to false."
						return
					}
			}
		#BDE Syntax variables
		#$bdeSyntaxBase = "Enable-BitLocker -MountPoint 'C:'"
		$bdeMountPoint = 'C:'
		$bdeErrorAction = "Stop"
		#$bde
		#If we successfully verifiedOU, add the SilentlyContinue parameter to the first Enable-BitLocker command
		#This is because the command errors out if GPO requires a RecoveryPassword
		#IF (!$verifiedOU)
		#	{
		#		Write-Output "Aborting Apply-BDE funciton because verifiedOU was set to false."
		#		return
		#	} 
		#Here lies a bug, if a recovery password is not required but the SkipHardwareTest paramater is true, SkipHardwareTest will not be honored
		#IF ($NoHardwareTest)
		#	{
		#		$bdeSyntaxBase = $bdeSyntaxBase + " -SkipHardwareTest"
		#	}
		
		#If the TPM exists use NewPIN and TPMandPinProtector parameters
		IF ($tpmStatus)
		{
			#$bdeSyntaxBase = $bdeSyntaxBase + " -TPMandPinProtector"
			#Convert NewPIN to a SecureString
			$secureString = ConvertTo-SecureString $NewPIN -AsPlainText -Force
			#$bdeSyntaxBase = $bdeSyntaxBase + " -Pin $secureString"
			#Write-Output "bdeSyntaxBase is $bdeSyntaxBase"
			#Write-Output "NewPIN is $NewPIN."
			IF ($RmmTool)
				{
					IF ($Testing -eq $false)
						{
							Enable-BitLocker -Pin $secureString -MountPoint "C:" -TPMandPinProtector | out-null
						}
						ELSE
						{
							Write-Output "Would execute a TPMandPinProtector Enable-BitLocker command in RMM Mode here but the Testing flag is set."
						}
				}
				ELSE
				{
					IF ($Testing -eq $false)
						{
							Enable-BitLocker -Pin $secureString -MountPoint "C:" -TPMandPinProtector
						}
						ELSE
						{
							Write-Output "Would execute a TPMandPinProtector Enable-BitLocker command here but the Testing flag is set."
						}
				}
		} 
		ELSE
			{
			#$bdeSyntaxBase = $bdeSyntaxBase + " -PasswordProtector"
			#Convert NewPassword to a SecureString
			$secureString = ConvertTo-SecureString $NewPassword -AsPlainText -Force
			#Write-Output "bdeSyntaxBase is $bdeSyntaxBase"
			#Write-Output "NewPassword is $NewPassword."
			#Enable-BitLocker $bdeSyntaxBase -Password $secureString
			IF ($RmmTool)
				{
					IF ($Testing -eq $false)
						{
							Enable-BitLocker -MountPoint "C:" -PasswordProtector -Password $secureString | out-null
						}
						ELSE
						{
							Write-Output "Would execute a PasswordProtector Enable-BitLocker command in RMM Mode here but the Testing flag is set."
						}
				}
				ELSE
				{
					IF (!Testing)
						{
							Enable-BitLocker -MountPoint "C:" -PasswordProtector -Password $secureString
						}
						ELSE
						{
							Write-Output "Would execute a PasswordProtector Enable-BitLocker command here but the Testing flag is set."
						}
				}
			}
		IF ($CreateRecoveryPassword)
			{
				#$bdeSyntaxRecoveryBase = "Enable-BitLocker -MountPoint C: -RecoveryPassword"
				#If NoHardwareTest is true add the SkipHardwareTest paramater
				IF ($NoHardwareTest)
					{
						IF ($RmmTool)
							{
								IF ($Testing -eq $false)
									{
										Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector -SkipHardwareTest | out-null
										return
									}
									ELSE
									{
										Write-Output "Would execute a RecoveryPasswordProtector Enable-BitLocker command in RMM Mode here, but the Testing flag is set."
									}
							}
							ELSE
							{
								IF ($Testing -eq $false)
									{
										Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector -SkipHardwareTest
									}
									ELSE
									{
										Write-Output "Would execute a RecoveryPasswordProtector Enable-BitLocker command here, but the Testing flag is set."
									}
							}
					}
				
				#Write-Output "bdeSyntaxRecoveryBase is $bdeSyntaxRecoveryBase"
				IF ($RmmTool)
					{
						IF ($Testing -eq $false)
							{
								Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector | out-null
							}
							ELSE
							{
								Write-Output "Would execute a RecoveryPasswordProtector Enable-BitLocker command in RMM Mode here, but the Testing flag is set."
							}
							
					}
					ELSE
					{
						IF ($Testing -eq $false)
							{
								Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector
							}
							ELSE
							{
								Write-Output "Would execute a RecoveryPasswordProtector Enable-BitLocker command here, but the Testing flag is set."
							}
					}
			}
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
		}
#OU detection
Detect-OU($VerifyOU)
Apply-BDE($tpmStatus,$NewPIN,$NewPassword,$verifiedOU,$CreateRecoveryPassword,$NoHardwareTest,$Testing)

#Cleanup and output steps

#Show us the final credential if required
IF ($displayCredential)
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
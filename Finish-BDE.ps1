#########################################################################
#																		#
#	Script Title: Finish-BDE											#
#	Author: Brennan Custard												#
#	Date: 8/26/2020														#
#	Description: This script accepts basic parameters to complete		#
#	the BDE process for a given OS disk in an endpoint.			 		#
#																		#
#########################################################################

#Min 6 char, used when TPM is available. Generally, use the last 6 chars
#of the serial number in all caps. 
#TODOif serial is not long enough, prepend the Client Identifier.
param ($NewPIN, $NewPassword, $VerifyOU, $CreateRecoveryPassword=$true, $CompanyIdentifier)


function Detect-OU {

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
				$Computer = Get-ADComputer $ComputerName -ErrorAction Stop
			} CATCH
				{
					Write-Output "VerifyOU was provided but cannot get computer information from AD!!!"
					return
					
				}
		#Get the current OU of the AD computer
		$OU = $Computer.DistinguishedName.SubString($Computer.DistinguishedName.IndexOf('OU='));
		
		#Test if the OU we're in at least a child of VerifyOU
		IF ($OU -match $VerifyOU)
			{
				Write-Output "Asset is in a child of the provided OU."
				Write-Output "Updating Group Policy..."
				gpupdate
				$verifiedOU = $true
				
				#Write-Output "VerifyOU is $VerifyOU"
				#Write-Output "OU is $OU"
			}
			ELSE
			{
				Write-Output "Asset is NOT in a child of the provided OU!!! Exiting..."
				$verifiedOU = $false
				#Write-Output "VerifyOU is $VerifyOU"
				#Write-Output "OU is $OU"

			}


}

#Get the serial number
$serial = (Get-CimInstance win32_bios).SerialNumber
$detectedPIN=($serial.Substring($serial.Length - 6)).ToUpper()

#IF NewPIN not provided detect and set it.
IF (!$NewPIN)
	{
		Write-Output "NewPIN not provided... parsing first PIN from serial number..."
		Write-Output "Detected Serial Number is $serial."
		$NewPIN = $detectedPIN
		Write-Output "NewPIN is $NewPIN"
	}




#Min 8 chars, used when no TPM is available. Generally, use last 8 chars 
#of the serial number. If serial is not long enough, prepend the Client
#Identifier.
#param ($NewPassword)


#Should be the DN of a parent OU we want the asset to be in before
#proceeding. Useful for ensuring GP is applied at time of encryption.
#param ($VerifyOU)


#Should be a Boolean instructing the script whether or not to add a 
#RecoveryPassword protector to the protected volume.
#param ($CreateRecoveryPassword=$true)



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
				Write-Output "PIN is at least 6 characters in length."
				#OU detection
				Detect-OU($VerifyOU)
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
			Write-Output "No TPM detected... verifying NewPassword..."
			#If NewPassword doesn't exist, detect the NewPIN value. If longer than 5 chars, prepend CompanyIdentifier.
			IF (!$NewPassword)
				{
					#Just use NewPIN if its long enough
					Write-Output "NewPassword not provided..."
					IF (($NewPIN).length -ge 8)
						{
							Write-Output "NewPIN is long enough to take the place of NewPassword... setting them equal."
							$NewPassword = $NewPIN
						}
						ELSE
							{
							Write-Output "NewPIN is not long enough to function as NewPassword..."
							IF ($CompanyIdentifier)
								{
									$CompanyIdentifier = $CompanyIdentifier.toUpper()
									#Add CompanyIdentifier and NewPIN together to make NewPassword
									$NewPassword = $CompanyIdentifier + $NewPIN
									#Check that NewPassword is at least 8 chars
									IF (($NewPassword).length -ge 8)
										{
											Write-Output "Successfully created NewPassword!!!"
											Write-Output "NewPassword is $NewPassword."
											#OU detection
											Detect-OU($VerifyOU)
										}
										ELSE
										{
											Write-Output "NewPassword is not long enough... Value is $NewPassword."
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



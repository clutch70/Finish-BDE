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
#of the serial number. if serial is not long enough, prepend the Client
#Identifier.
param ($NewPIN)


#Min 8 chars, used when no TPM is available. Generally, use last 8 chars 
#of the serial number. If serial is not long enough, prepend the Client
#Identifier.
param ($NewPassword)


#Should be the DN of a parent OU we want the asset to be in before
#proceeding. Useful for ensuring GP is applied at time of encryption.
param ($VerifyOU)
param ($CreateRecoveryPassword)


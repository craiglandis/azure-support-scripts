############################################################################
# List of steps to remove the rescue resource group rescueproblemVM1
############################################################################
# Step 0: Logs-in to Azure
Login-AzureRmAccount
# Step 1: Setting the context to SubscriptionID :927f2a7f-5662-40f2-8d19-521fe803ed2e
$authContext = Set-AzureRmContext -Subscription 927f2a7f-5662-40f2-8d19-521fe803ed2e
# Step 1: Removing the rescue resource Group rescueproblemVM1
$result = Remove-AzureRmResourceGroup -Name rescueproblemVM1

# AWS Config custom rule for evaluating Security group egress rule
**Check if all lambdas belonging to a specific security group are in compliance by evaluating all egress ip ranges not being 0.0.0.0/0**

## Logic
1. **'index.js'**
- Takes the AWS Config event as input containing the rule parameter (in this case a vpcid). Note that AWS Config runs this as a Scheduled notification.
- Retrieves all lambdas within VPC
- Uses lambda names to get associated security groups
- Filter those security groups that have the 0.0.0.0/0 outbound rule
- Send the evaluation result back to config



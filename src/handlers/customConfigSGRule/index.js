const configClient = require("aws-sdk/clients/configservice"); 
const ec2Client = require("aws-sdk/clients/ec2");
const lambdaClient = require("aws-sdk/clients/lambda");

const ec2 = new ec2Client({ region: process.env.AWS_REGION });
const lambda = new lambdaClient({ region: process.env.AWS_REGION });
const config = new configClient(); 
const COMPLIANCE_STATES = {
  COMPLIANT: "COMPLIANT",
  NON_COMPLIANT: "NON_COMPLIANT",
  NOT_APPLICABLE: "NOT_APPLICABLE",
};

// Checks whether the invoking event is ScheduledNotification
function isScheduledNotification(invokingEvent) {
  return invokingEvent.messageType === "ScheduledNotification";
}

// Evaluates the configuration of the egress rule in the security group
const evaluateCompliance = async (vpcId) => {
  const getLambdaInVPC = await ec2
    .describeNetworkInterfaces({
      Filters: [{ Name: "vpc-id", Values: [vpcId] }],
    })
    .promise();
  const lambdaList = [];

  getLambdaInVPC.NetworkInterfaces.forEach((item) => {
    lambdaList.push(
      item.Description.split("AWS Lambda VPC ENI-")[1].split("-")[0]
    );
  });
  if (lambdaList) {
    const uniqueLambdaNames = [...new Set(lambdaList)];

    const getLambdaSGId = [];
    for (const item in uniqueLambdaNames) {
      const lambdaInfo = await lambda
        .getFunction({ FunctionName: uniqueLambdaNames[item] })
        .promise();
      lambdaInfo.Configuration.VpcConfig.SecurityGroupIds.forEach((item) => {
        getLambdaSGId.push(item);
      });
    }
    const uniqueSGId = [...new Set(getLambdaSGId)];

    let complianceSGList = [];
    uniqueSGId.forEach((id) => {
        complianceSGList.push({
            Id: id,
            Compliance: COMPLIANCE_STATES.COMPLIANT,
          })
    });
    const checkSGEgressInternetRule = await ec2
      .describeSecurityGroups({
        GroupIds: [...uniqueSGId],
        Filters: [{ Name: "egress.ip-permission.cidr", Values: ["0.0.0.0/0"] }],
      })
      .promise();

    if (checkSGEgressInternetRule.SecurityGroups) {
      checkSGEgressInternetRule.SecurityGroups.forEach((item) => {
        const indexToUpdate = complianceSGList.findIndex((obj => obj.Id == item.GroupId));
        complianceSGList[indexToUpdate].Compliance = COMPLIANCE_STATES.NON_COMPLIANT;
      });
      console.log(JSON.stringify(complianceSGList))
      return complianceSGList;
    }
  } else {
    return [{ Id: vpcId }, { Compliance: COMPLIANCE_STATES.NOT_APPLICABLE }];
  }
};

exports.handler = async (event, context) => {
  // Parses the invokingEvent and ruleParameters values, which contain JSON objects passed as strings.
  console.log(JSON.stringify(event));
  const invokingEvent = JSON.parse(event.invokingEvent);
  const ruleParameters = JSON.parse(event.ruleParameters);


  if (isScheduledNotification(invokingEvent)) {
    // Passes the vpcid from the config rule parameter
    const checkCompliance = await evaluateCompliance(ruleParameters.vpcid);
    const putEvaluationsRequest = {
      ResultToken: event.resultToken,
    };
    putEvaluationsRequest.Evaluations = [];
    checkCompliance.forEach((item) => {
      putEvaluationsRequest.Evaluations.push({
        ComplianceResourceType: "AWS::EC2::SecurityGroup",
        ComplianceResourceId: item.Id,
        ComplianceType: item.Compliance,
        OrderingTimestamp: new Date(),
      });
    });
    // Sends the evaluation results to AWS Config.
    const configResponse = await config.putEvaluations(putEvaluationsRequest).promise();
    return configResponse
  } else {
    console.log("Not a scheduled event");
  }
};

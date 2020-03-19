//During the automated test the env variable, We will set it to "test"
process.env.NODE_ENV = "test";
process.env.MONGODB_URL = "mongodb://127.0.0.1:27017/nodejs-api-boilerplate-test";

//Require the dev-dependencies
import chai from "chai";
import chaiHttp from "chai-http";
import app from "../src/app";
let should = chai.should();
chai.use(chaiHttp);

//Export this to use in multiple files
export default {
	chai: chai,
	server: app,
	should: should
};
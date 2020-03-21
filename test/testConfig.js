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
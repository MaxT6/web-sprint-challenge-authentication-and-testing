const router = require("express").Router();
const Users = require("./users-model");
const { restricted } = require("../middleware/restricted");

module.exports = router;
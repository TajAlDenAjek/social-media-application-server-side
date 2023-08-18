const fs = require('fs').promises;
const path=require('path');
const configOptions=
{
  development:{
    username: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
    port: process.env.DATABASE_PORT,
    database: process.env.DATABASE_NAME,
    host: process.env.DATABASE_HOST,
    dialect: process.env.DATABASE_DIALECT,
    logging:false,
  },
  test:{
    username: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
    port: process.env.DATABASE_PORT,
    database: process.env.DATABASE_NAME,
    host: process.env.DATABASE_HOST,
    dialect: process.env.DATABASE_DIALECT,
    logging:false,
  },
  production: {
    username: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
    port: process.env.DATABASE_PORT,
    database: process.env.DATABASE_NAME,
    host: process.env.DATABASE_HOST,
    dialect: process.env.DATABASE_DIALECT,
    logging:false,
  },
};

const saveConfig=async()=>
{
  try {
    const json=JSON.stringify(configOptions);    
    await fs.writeFile(path.join(__dirname,'config.json'),json);
  } catch (error) {
    console.log(error);
  }
}

saveConfig();
module.exports=configOptions;

// int dpc_radius_attr(char *p_radius_attr, uint32_t radius_attr_len,user_info_t* user_info)
// {
//  uint32_t radius_attr_num = 0;
//  uint32_t radius_attr_size = sizeof(radius_attr_t);
//  uint32_t ip_len = 0;
//  uint32_t total_size = 0;
//  uint32_t acct_status = 0;
//  uint32_t radius_status = 0;
//  char    *p_buf = NULL;
//  radius_attr_t   *p_cur_attr = NULL;
//  int count = 0;

//  //开始遍历Radius attr中各元素
//  while (radius_attr_len > total_size + radius_attr_size){
//   //不能超出最大attr数量
//   if (radius_attr_num > RADIUS_ATTR_MAX_COUNT){
//    //printf("raidus attr num is too large: %u\n", radius_attr_num);
//    break;
//   }
//   p_cur_attr = (radius_attr_t *)(p_radius_attr + total_size);
//   //去除为0的错误情况, 防止死循环
//   if (p_cur_attr->len == 0){
//    //printf("cur attr len is 0\n");
//    return -1;
//   }
//   //对attr中的type进行判断
//   switch (p_cur_attr->type)
//   {
//    case RADIUS_ATTR_NAME:
//     if((p_cur_attr->len <= radius_attr_size))
//      return -1;
//     if (p_cur_attr->len - radius_attr_size > USER_NAME_SIZE){
//      memcpy(user_info->name, p_cur_attr + 1, USER_NAME_SIZE);
//     } else {
//      memcpy(user_info->name, p_cur_attr + 1, p_cur_attr->len - radius_attr_size);
//     }
//     radius_status++;
//     break;
//    case RADIUS_ATTR_IP:
//     if((p_cur_attr->len <= radius_attr_size))
//      return -1;
//     p_buf = (char*)p_cur_attr;
//     memcpy(&(user_info->ip), p_cur_attr + 1, sizeof(uint32_t));
//     user_info->ip = ntohl(user_info->ip);
//     radius_status++;
//     break;
//    case RADIUS_ATTR_ACCT_STATUS_TYPE:
//     if ((p_cur_attr->len <= radius_attr_size) ||
//       (p_cur_attr->len - radius_attr_size) >
//       sizeof(int))
//     {
//      //printf("RADIUS_ACCT_STATUS_TYPE attr error\n");
//      return -1;
//     }
//     p_buf = (char *)p_cur_attr;
//     acct_status = ntohl(*((uint32_t *)(p_buf + radius_attr_size)));
//     switch (acct_status)
//     {
//      case RADIUS_ACCT_STATUS_START:
//       user_info->flag = USER_ONLINE;
//       break;
//      case RADIUS_ACCT_STATUS_STOP:
//       user_info->flag = USER_OFFLINE;
//       break;
//      case RADIUS_ACCT_STATUS_UPDATE:
//       user_info->flag = USER_ONLINE;
//       break;
//      default:
//       //printf("RADIUS_ACCT_STATUS_TYPE not care!\n");
//       break;
//     }
//     //DEBUG("online flag: %x", user_info->flag);
//     radius_status++;
//     break;
//    default:
//     break;
//   }
//   radius_attr_num++;
//   total_size += p_cur_attr->len;
//   //当NAME, IMSI, IP, ACCT及TYPE都获取成功后退出
//   if (radius_status == RADIUS_FINSHED_STATUS){
//    return 0;
//   }
//  }
//  return count;
// }
package com.greedy.semi.member.controller;

import java.util.Date;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.member.dto.OrderInfoDTO;
import com.greedy.semi.member.dto.PayDTO;
import com.greedy.semi.member.dto.ProductDTO;
import com.greedy.semi.member.service.OrderInfoService;
import com.greedy.semi.member.service.PayService;
import com.greedy.semi.member.service.ProductService;
import com.greedy.semi.trade.dto.TradeDTO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
public class PayController {
	
    private final PayService payService;
    private final OrderInfoService orderInfoService;
    private final ProductService productService;
    
    private PayController(ProductService productService, PayService payService, OrderInfoService orderInfoService)
    {
    	this.payService = payService;
    	this.orderInfoService=orderInfoService;
    	this.productService = productService;
    }
    
    @ResponseBody
	@PostMapping("/user/mypage")
	public String chargetPoint(@RequestParam("amount") int payAmt, @AuthenticationPrincipal MemberDTO member,@RequestParam("sellNo") Long sellNo)
 {
    	
    	PayDTO pay = new PayDTO();
    	OrderInfoDTO order = new OrderInfoDTO();
    	TradeDTO trade = new TradeDTO();
		ProductDTO product = new ProductDTO();
		
    	/* OrderInfo 저장*/
    	/* 넘겨받은 sellNo 저장 */	
    	trade.setSellNo(sellNo);
    	
    	/* MemberId저장 */
    	order.setMember(member);
    	
        /* 금액 별로 상품 DTO 가져와서 productCode저장 */
       /* ProductDTO product = productService.findCodeByPayAmt(payAmt);*/
        /*product.setProductCode(code);
        log.info("productDTO",product);*/
        

    	if(payAmt < 10000)
    	{
    		trade.setPayStatus("N");
    	}
    	else 
    	{
    		trade.setPayStatus("Y");
    		if(payAmt == 10000)
    		{
    			product.setProductCode(1);
    		}
    		else if(payAmt == 20000)
    		{
    			product.setProductCode(2);
    		}
    		else 
    		{
    			product.setProductCode(3);
    		}
    	}
    	log.info("tradeDTO",trade);
    	payService.updatePayStatus(trade);
    	
		order.setProduct(product);
    	order.setTrade(trade);

		//orderInfoService.order(order);
		
		 /* pay OrderInfoDTO 저장 */
		pay.setOrderInfo(order);
		String str2 = "" + pay.getOrderInfo();
    	/* pay Amount 저장 */
		pay.setPayAmt(payAmt);
		String str = "" + pay.getPayAmt();
		log.info("결제금액 : "+str + str2);
		/* pay date 저장*/
        Date date = new Date();
        long timeInMilliSeconds = date.getTime();
        java.sql.Date sqlDate = new java.sql.Date(timeInMilliSeconds);
        System.out.println("SQL Date: " + sqlDate);
        log.info(sqlDate.toString());
        pay.setPayDate(sqlDate);
       
    	
    	
        payService.payAmount(pay);
    	
        return "redirect:/";	
        }
}
